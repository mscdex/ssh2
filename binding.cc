#include <stdio.h>
#include <assert.h>

#ifdef _WIN32
# include <Ws2tcpip.h>
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

static Persistent<String> emit_symbol;
static Persistent<FunctionTemplate> SSHSession_constructor;

int STATE_INIT = 0,
    STATE_HANDSHAKE = 1,
    STATE_AUTH = 2;

class SSHSession : public ObjectWrap {
  public:
    uv_os_sock_t sock;
    uv_poll_t poll_handle;
    bool hadError;
    int state;
    int events;
    LIBSSH2_SESSION *session;

    SSHSession() {
      session = NULL;
      init();
    }
    ~SSHSession() {
      close();
    }
    void init() {
      HandleScope scope;
      if (!session) {
        hadError = false;
        state = STATE_INIT;
        events = 0;
        session = libssh2_session_init();
        if (session == NULL) {
          ThrowException(Exception::Error(
            String::New("Error while initializing session"))
          );
        }
        libssh2_session_set_blocking(session, 0);
      }
    }
    void close() {
      HandleScope scope;
      if (session != NULL) {
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
      }
    }
    static void EmitLibError(SSHSession* obj) {
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
    static void Poll_cb(uv_poll_t* handle, int status, int events) {
      HandleScope scope;
      SSHSession* obj = (SSHSession*) handle->data;
      assert(status == 0);
      int rc = 0;
      int new_events = 0;
      int dirs = 0;
      while (!rc) {
        if (obj->state == STATE_INIT)
          rc = libssh2_session_handshake(obj->session, obj->sock);
        else if (obj->state == STATE_HANDSHAKE) {
          const char* fingerprint =
              libssh2_hostkey_hash(obj->session, LIBSSH2_HOSTKEY_HASH_SHA1);
          rc = libssh2_userauth_password(obj->session, "username", "password");
        } else if (obj->state == STATE_AUTH) {
          
        }
        if (!rc)
          ++obj->state;
      }
      if (libssh2_session_last_errno(obj->session) != LIBSSH2_ERROR_EAGAIN)
        EmitLibError(obj);
      else {
        dirs = libssh2_session_block_directions(obj->session);
        if (dirs & LIBSSH2_SESSION_BLOCK_INBOUND)
          new_events |= UV_READABLE;
        if (dirs & LIBSSH2_SESSION_BLOCK_OUTBOUND)
          new_events |= UV_WRITABLE;
        if (new_events != obj->events) {
          obj->events = new_events;
          uv_poll_start(&obj->poll_handle, new_events, Poll_cb);
        }
      }
    }
    static void Close_cb(uv_handle_t* handle) {
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
      HandleScope scope;
      SSHSession* obj = ObjectWrap::Unwrap<SSHSession>(args.This());
      obj->close();
      uv_close((uv_handle_t*) &obj->poll_handle, Close_cb);
      return Undefined();
    }

    static Handle<Value> Connect(const Arguments& args) {
      HandleScope scope;

      if (args.Length() < 2 || !args[0]->IsString() || !args[1]->IsUint32()) {
        return ThrowException(Exception::Error(
          String::New("Port and ip address arguments expected"))
        );
      }

      SSHSession* obj = ObjectWrap::Unwrap<SSHSession>(args.This());

      obj->init();

      String::AsciiValue ip_address(args[0]);
      int port = args[1]->Int32Value();
      int r;

      if (isIPv4(*ip_address))
        obj->sock = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
      else if (isIPv6(*ip_address))
        obj->sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_IP);
      else {
        return ThrowException(Exception::Error(
          String::New("Invalid IP address"))
        );
      }
#ifndef _WIN32
      {
        /* Allow reuse of the port. */
        int yes = 1;
        r = setsockopt(obj->sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);
      }
#endif
#ifdef _WIN32
      unsigned long on = 1;
      r = ioctlsocket(obj->sock, FIONBIO, &on);
#else
      int flags = fcntl(obj->sock, F_GETFL, 0);
      r = fcntl(obj->sock, F_SETFL, flags | O_NONBLOCK);
#endif
      r = uv_poll_init_socket(uv_default_loop(), &obj->poll_handle, obj->sock);
      obj->poll_handle.data = obj;
      obj->events = UV_WRITABLE;
      r = uv_poll_start(&obj->poll_handle, UV_WRITABLE, Poll_cb);
      if (isIPv4(*ip_address)) {
        struct sockaddr_in address = uv_ip4_addr(*ip_address, port);
        r = connect(obj->sock, (struct sockaddr*) &address, sizeof address);
      } else {
        struct sockaddr_in6 address = uv_ip6_addr(*ip_address, port);
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
