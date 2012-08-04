// TODO:
//        * getaddrinfo() for hostname
//        * connection timeout
//        * authentication via ssh agent
//        * post-authentication functionality -- sftp, shell exec, port forward,
//          etc.

#include <stdio.h>

#ifdef _WIN32
# include <Ws2tcpip.h>
# ifdef _MSC_VER
#  define strdup _strdup
# endif
#endif

#include <node.h>
#include <node_buffer.h>

#include <libssh2.h>

using namespace node;
using namespace v8;

bool isIPv4(char* ip) {
  struct sockaddr_in sa;
#ifdef _WIN32
  int saSize = sizeof(struct sockaddr_in);
  return (WSAStringToAddress(ip, AF_INET, NULL, (LPSOCKADDR)&sa, &saSize) == 0);
#else
  return (inet_pton(AF_INET, ip, &(sa.sin_addr)) == 1);
#endif
}

bool isIPv6(char* ip) {
  struct sockaddr_in6 sa;
#ifdef _WIN32
  int saSize = sizeof(struct sockaddr_in6);
  return (WSAStringToAddress(ip, AF_INET6, NULL, (LPSOCKADDR)&sa, &saSize) == 0);
#else
  return (inet_pton(AF_INET6, ip, &(sa.sin6_addr)) == 1);
#endif
}

int set_sock_keepalive(uv_os_sock_t socket, int enable, unsigned int delay) {
#ifdef _WIN32
  if (setsockopt(socket,
                 SOL_SOCKET,
                 SO_KEEPALIVE,
                 (const char*)&enable,
                 sizeof enable) == -1)
    return -1;
  if (enable && setsockopt(socket,
                           IPPROTO_TCP,
                           SO_KEEPALIVE,
                           (const char*)&delay,
                           sizeof delay) == -1)
    return -1;
#else
  if (setsockopt(socket,
                 SOL_SOCKET,
                 SO_KEEPALIVE,
                 &enable,
                 sizeof enable) == -1)
    return -1;
#ifdef TCP_KEEPIDLE
  if (enable && setsockopt(socket,
                           IPPROTO_TCP,
                           TCP_KEEPIDLE,
                           &delay,
                           sizeof delay) == -1)
    return -1;
#endif
#ifdef TCP_KEEPALIVE
  if (enable && setsockopt(socket,
                           IPPROTO_TCP,
                           TCP_KEEPALIVE,
                           &delay,
                           sizeof delay) == -1)
    return -1;
#endif
#endif
  return 0;
}

static Persistent<String> emit_symbol;
static Persistent<FunctionTemplate> SSHSession_constructor;

int STATE_INIT = 0,
    STATE_HANDSHAKE = 1,
    STATE_FINGERPRINT = 2,
    STATE_AUTH = 3;
int NO_EVENTS = 0;
unsigned int DEFAULT_KEEPALIVE_INTVL = 60; // in seconds

struct ses_config {
  // u/p auth
  char* username;
  char* password;
  // key auth
  char* priv_key;
  char* pub_key;
  char* passphrase;
  // misc options
  bool compress;
  unsigned int keepalive_intvl;
};

class SSHSession : public ObjectWrap {
  public:
    uv_os_sock_t sock;
    uv_poll_t poll_handle;
    uv_timer_t keepalive_timer;
    bool hadError;
    int state;
    int events;
    struct ses_config config;
    LIBSSH2_SESSION *session;

    SSHSession() {
printf("SSHSession()\n");
      session = NULL;
      poll_handle.type = UV_UNKNOWN_HANDLE;
      keepalive_timer.type = UV_UNKNOWN_HANDLE;
      //init();
    }
    ~SSHSession() {
printf("~SSHSession()\n");
      close();
    }
    void init() {
printf("init()\n");
      HandleScope scope;
      if (session)
        close();

      hadError = false;
      state = STATE_INIT;
      events = 0;
      config.username = NULL;
      config.password = NULL;
      config.priv_key = NULL;
      config.pub_key = NULL;
      config.compress = false;
      config.keepalive_intvl = DEFAULT_KEEPALIVE_INTVL;
      session = libssh2_session_init();
      if (session == NULL) {
        ThrowException(Exception::Error(
          String::New("Error while initializing session"))
        );
      }
      libssh2_session_set_blocking(session, 0);
    }
    void close() {
printf("close()\n");
      HandleScope scope;
      if (session) {
        if (poll_handle.type == UV_POLL)
          uv_poll_stop(&poll_handle);
        if (keepalive_timer.type == UV_TIMER)
          uv_timer_stop(&keepalive_timer);
        if (config.username)
          free(config.username);
        if (config.password)
          free(config.password);
        if (config.priv_key)
          free(config.priv_key);
        if (config.pub_key)
          free(config.pub_key);
        int rc = libssh2_session_free(session);
        if (rc != NULL) {
          char msg[128];
          sprintf(msg, "Error while freeing session: %d", rc);
          ThrowException(Exception::Error(String::New(msg)));
        }
        session = NULL;
      }
      if (sock != NULL) {
        int r;
#ifdef _WIN32
        r = shutdown(sock, SD_SEND);
        r = closesocket(sock);
#else
        r = shutdown(sock, SHUT_WR);
        r = close(sock);
#endif
        sock = NULL;
      }
    }
    static void EmitLibError(SSHSession* obj) {
printf("EmitLibError()\n");
      HandleScope scope;
      char* msg;
      msg = (char*)malloc(512);
      libssh2_session_last_error(obj->session, &msg, NULL, 0);
      Local<Function> Emit = Local<Function>::Cast(obj->handle_->Get(emit_symbol));
      Local<Value> emit_argv[2] = {
        String::New("error"),
        Exception::Error(String::New(msg))
      };
      TryCatch try_catch;
      Emit->Call(obj->handle_, 2, emit_argv);
      if (try_catch.HasCaught())
        FatalException(try_catch);
      free(msg);
      obj->hadError = true;
      obj->close();
      uv_close((uv_handle_t*) &obj->poll_handle, Close_cb);
    }
    static void Timer_cb(uv_timer_t* handle, int status) {
      HandleScope scope;
      assert(status == 0);
      SSHSession* obj = (SSHSession*) handle->data;
      int next_intvl,
          r = libssh2_keepalive_send(obj->session, &next_intvl);
      if (r == 0) {
printf("sent keepalive probe (next one in %d secs)\n", next_intvl);
        uv_timer_stop(&obj->keepalive_timer);
        uv_timer_start(&obj->keepalive_timer, Timer_cb, next_intvl * 1000, 0);
      }
    }
    static void Poll_cb(uv_poll_t* handle, int status, int events) {
      HandleScope scope;
      SSHSession* obj = (SSHSession*) handle->data;
      assert(status == 0);
      int rc = 0;
      int new_events = NO_EVENTS;
      int dirs = 0;
      while (!rc) {
        if (obj->state == STATE_INIT)
          rc = libssh2_session_handshake(obj->session, obj->sock);
        else if (obj->state == STATE_HANDSHAKE) {
          const char* fingerprint =
              libssh2_hostkey_hash(obj->session, LIBSSH2_HOSTKEY_HASH_SHA1);
          Local<Function> Emit = Local<Function>::Cast(obj->handle_->Get(emit_symbol));
          Buffer* buffer = Buffer::New((char*)fingerprint, 20);
          Local<Value> emit_argv[2] = {
            String::New("fingerprint"),
            Local<Object>::New(buffer->handle_)
          };
          TryCatch try_catch;
          Emit->Call(obj->handle_, 2, emit_argv);
          if (try_catch.HasCaught())
            FatalException(try_catch);
          // the connection was ended from an event handler
          if (!obj->session)
            return;
          rc = 0;
        } else if (obj->state == STATE_FINGERPRINT) {
          if (obj->config.password) {
            rc = libssh2_userauth_password(obj->session,
                                           obj->config.username,
                                           obj->config.password);
          } else {
            rc = libssh2_userauth_publickey_fromfile(obj->session,
                                                     obj->config.username,
                                                     obj->config.pub_key,
                                                     obj->config.priv_key,
                                                     obj->config.passphrase);
          }
          Local<Function> Emit = Local<Function>::Cast(obj->handle_->Get(emit_symbol));
          Local<Value> emit_argv[1] = { String::New("authenticated") };
          TryCatch try_catch;
          Emit->Call(obj->handle_, 1, emit_argv);
          if (try_catch.HasCaught())
            FatalException(try_catch);
        } else if (obj->state == STATE_AUTH) {
printf("authenticated!\n");
          if (obj->config.keepalive_intvl > 0) {
            uv_timer_init(uv_default_loop(), &obj->keepalive_timer);
            obj->keepalive_timer.data = obj;
            libssh2_keepalive_config(obj->session, 0, obj->config.keepalive_intvl);
            Timer_cb(&obj->keepalive_timer, 0);
          }
          rc = 0;
        } else {
          rc = LIBSSH2_ERROR_EAGAIN;
          break;
        }
        if (!rc)
          ++obj->state;
      }
      //if (libssh2_session_last_errno(obj->session) != LIBSSH2_ERROR_EAGAIN)
      if (rc != LIBSSH2_ERROR_EAGAIN) {
        if (rc == LIBSSH2_ERROR_SOCKET_DISCONNECT) {
          obj->close();
          uv_close((uv_handle_t*) &obj->poll_handle, Close_cb);
        } else
          EmitLibError(obj);
      } else {
        dirs = libssh2_session_block_directions(obj->session);
        if (dirs & LIBSSH2_SESSION_BLOCK_INBOUND)
          new_events |= UV_READABLE;
        if (dirs & LIBSSH2_SESSION_BLOCK_OUTBOUND)
          new_events |= UV_WRITABLE;
        if (new_events != obj->events) {
printf("attempt to change events from %d to %d\n", obj->events, new_events);
          obj->events = new_events;
          // Even if libssh2 says there's nothing left to do, we still want to
          // keep the event loop alive. For some silly reason, we need to make
          // sure we have both readable and writable events set in this case so
          // that Poll_cb() keeps getting called, otherwise libuv will exit the
          // event loop after some period of time of no poll events. This is
          // very inefficient since we don't need to be notified of *any* events
          // until we perform some action after authentication. Ugh.....
          if (new_events == NO_EVENTS)
            new_events = UV_WRITABLE | UV_READABLE;
          uv_poll_start(&obj->poll_handle, new_events, Poll_cb);
        }
      }
    }
    static void Close_cb(uv_handle_t* handle) {
printf("Close_cb()\n");
      HandleScope scope;
      SSHSession* obj = (SSHSession*) handle->data;
      Local<Function> Emit = Local<Function>::Cast(obj->handle_->Get(emit_symbol));
      TryCatch try_catch;
      if (obj->hadError) {
        Local<Value> emit_argv[2] = {
          String::New("close"),
          Local<Boolean>::New(Boolean::New(obj->hadError))
        };
        Emit->Call(obj->handle_, 2, emit_argv);
      } else {
        Local<Value> emit_argv[1] = {
          String::New("end")
        };
        Emit->Call(obj->handle_, 1, emit_argv);
      }
      if (try_catch.HasCaught())
        FatalException(try_catch);
    }

    static Handle<Value> New(const Arguments& args) {
      HandleScope scope;

      if (!args.IsConstructCall()) {
        return ThrowException(Exception::TypeError(
          String::New("Use `new` to create instances of this object."))
        );
      }

      SSHSession* obj = new SSHSession();
      obj->Wrap(args.This());

      return args.This();
    }

    static Handle<Value> Close(const Arguments& args) {
printf("Close()\n");
      HandleScope scope;
      SSHSession* obj = ObjectWrap::Unwrap<SSHSession>(args.This());
      obj->close();
      uv_close((uv_handle_t*) &obj->poll_handle, Close_cb);
      return Undefined();
    }

    static Handle<Value> Connect(const Arguments& args) {
      HandleScope scope;

      if (args.Length() < 1 || !args[0]->IsObject()) {
        return ThrowException(Exception::Error(
          String::New("Missing connection configuration object"))
        );
      }

      SSHSession* obj = ObjectWrap::Unwrap<SSHSession>(args.This());

      Local<Object> cfg = args[0]->ToObject();
      Local<Value> username_v = cfg->Get(String::New("username"));
      Local<Value> password_v = cfg->Get(String::New("password"));
      Local<Value> priv_key_v = cfg->Get(String::New("priv_key"));
      Local<Value> pub_key_v = cfg->Get(String::New("pub_key"));
      Local<Value> passphrase_v = cfg->Get(String::New("key_phrase"));
      Local<Value> compress_v = cfg->Get(String::New("compress"));
      Local<Value> keepalive_v = cfg->Get(String::New("keepalive"));
      obj->init();
      if (!username_v->IsString() || username_v->ToString()->Length() == 0) {
        obj->close();
        return ThrowException(Exception::Error(
          String::New("Missing username"))
        );
      } else {
        String::Utf8Value username_s(username_v);
        obj->config.username = strdup(*username_s);
      }
      if (password_v->IsString() && password_v->ToString()->Length() > 0) {
        String::Utf8Value password_s(password_v);
        obj->config.password = strdup(*password_s);
      } else if (priv_key_v->IsString()
                 && priv_key_v->ToString()->Length() > 0
                 && pub_key_v->IsString()
                 && pub_key_v->ToString()->Length() > 0
                 && passphrase_v->IsString()
                 && passphrase_v->ToString()->Length() > 0) {
        String::Utf8Value priv_key_s(priv_key_v);
        obj->config.priv_key = strdup(*priv_key_s);

        String::Utf8Value pub_key_s(pub_key_v);
        obj->config.pub_key = strdup(*pub_key_s);

        String::Utf8Value passphrase_s(passphrase_v);
        obj->config.passphrase = strdup(*passphrase_s);
      } else {
        obj->close();
        return ThrowException(Exception::Error(
          String::New("Must use either password or key-based authentication"))
        );
      }
      obj->config.compress = (compress_v->IsBoolean()
                              && compress_v->BooleanValue());
      if (keepalive_v->IsUint32())
        obj->config.keepalive_intvl = keepalive_v->Uint32Value();
      else if (keepalive_v->IsBoolean() && !keepalive_v->BooleanValue())
        obj->config.keepalive_intvl = 0;

      libssh2_session_flag(obj->session, LIBSSH2_FLAG_COMPRESS,
                           obj->config.compress ? 1 : 0);

      Local<Value> host_v = cfg->Get(String::New("host"));
      Local<Value> port_v = cfg->Get(String::New("port"));
      if (!host_v->IsString() || host_v->ToString()->Length() == 0) {
        obj->close();
        return ThrowException(Exception::Error(
          String::New("Missing hostname/ip address"))
        );
      } else if (!port_v->IsUint32()) {
        obj->close();
        return ThrowException(Exception::Error(
          String::New("Missing port number"))
        );
      }

      String::AsciiValue host_s(host_v);
      unsigned int port = port_v->Uint32Value();
      int r;

      if (isIPv4(*host_s))
        obj->sock = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
      else if (isIPv6(*host_s))
        obj->sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_IP);
      else {
        obj->close();
        return ThrowException(Exception::Error(
          String::New("Invalid IP address"))
        );
      }
      if (set_sock_keepalive(obj->sock, 1, 60) != 0) {
        printf("keepalive error #: %d\n", WSAGetLastError());
        assert(1==0);
      }
#ifdef _WIN32
      unsigned long on = 1;
      r = ioctlsocket(obj->sock, FIONBIO, &on);
#else
      {
        /* Allow reuse of the port. */
        int yes = 1;
        r = setsockopt(obj->sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);
      }
      int flags = fcntl(obj->sock, F_GETFL, 0);
      r = fcntl(obj->sock, F_SETFL, flags | O_NONBLOCK);
#endif
      r = uv_poll_init_socket(uv_default_loop(), &obj->poll_handle, obj->sock);
      obj->poll_handle.data = obj;
      obj->events = UV_WRITABLE;
      r = uv_poll_start(&obj->poll_handle, UV_WRITABLE, Poll_cb);
      if (isIPv4(*host_s)) {
        struct sockaddr_in address = uv_ip4_addr(*host_s, port);
        r = connect(obj->sock, (struct sockaddr*) &address, sizeof address);
      } else {
        struct sockaddr_in6 address = uv_ip6_addr(*host_s, port);
        r = connect(obj->sock, (struct sockaddr*) &address, sizeof address);
      }
      return scope.Close(v8::True());
    }

    static void Initialize(Handle<Object> target) {
      HandleScope scope;

      Local<FunctionTemplate> tpl = FunctionTemplate::New(New);
      Local<String> name = String::NewSymbol("Session");

      SSHSession_constructor = Persistent<FunctionTemplate>::New(tpl);
      SSHSession_constructor->InstanceTemplate()->SetInternalFieldCount(1);
      SSHSession_constructor->SetClassName(name);

      NODE_SET_PROTOTYPE_METHOD(SSHSession_constructor, "connect", Connect);
      NODE_SET_PROTOTYPE_METHOD(SSHSession_constructor, "end", Close);

      int rc = libssh2_init(NULL);
      if (rc != NULL) {
        char msg[128];
        sprintf(msg, "Error while initializing libssh2: %d", rc);
        ThrowException(Exception::Error(String::New(msg)));
      }
      emit_symbol = NODE_PSYMBOL("emit");
      target->Set(name, SSHSession_constructor->GetFunction());
    }
};

static Handle<Value> Version(const Arguments& args) {
  HandleScope scope;
  return scope.Close(String::New(libssh2_version(NULL)));
}

extern "C" {
  void init(Handle<Object> target) {
    HandleScope scope;
    SSHSession::Initialize(target);
    target->Set(String::NewSymbol("version"),
                FunctionTemplate::New(Version)->GetFunction());
  }

  NODE_MODULE(ssh2, init);
}
