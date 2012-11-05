var i = 0, keys, len;

var MESSAGE = exports.MESSAGE = {
  // Transport layer protocol -- generic (1-19)
  DISCONNECT: 1,
  IGNORE: 2,
  UNIMPLEMENTED: 3,
  DEBUG: 4,
  SERVICE_REQUEST: 5,
  SERVICE_ACCEPT: 6,

  // Transport layer protocol -- algorithm negotiation (20-29)
  KEXINIT: 20,
  NEWKEYS: 21,

  // Transport layer protocol -- key exchange method-specific (30-49)
  KEXDH_INIT: 30,
  KEXDH_REPLY: 31,

  // User auth protocol -- generic (50-59)
  USERAUTH_REQUEST: 50,
  USERAUTH_FAILURE: 51,
  USERAUTH_SUCCESS: 52,
  USERAUTH_BANNER: 53,

  // User auth protocol -- user auth method-specific (60-79)

  // Connection protocol -- generic (80-89)
  GLOBAL_REQUEST: 80,
  REQUEST_SUCCESS: 81,
  REQUEST_FAILURE: 82,

  // Connection protocol -- channel-related (90-127)
  CHANNEL_OPEN: 90,
  CHANNEL_OPEN_CONFIRMATION: 91,
  CHANNEL_OPEN_FAILURE: 92,
  CHANNEL_WINDOW_ADJUST: 93,
  CHANNEL_DATA: 94,
  CHANNEL_EXTENDED_DATA: 95,
  CHANNEL_EOF: 96,
  CHANNEL_CLOSE: 97,
  CHANNEL_REQUEST: 98,
  CHANNEL_SUCCESS: 99,
  CHANNEL_FAILURE: 100

  // Reserved for client protocols (128-191)

  // Local extensions (192-155)
};
for (i=0,keys=Object.keys(MESSAGE),len=keys.length; i<len; ++i)
  MESSAGE[MESSAGE[keys[i]]] = keys[i];
// context-specific message codes:
exports.USERAUTH_PASSWD_CHANGEREQ = 60;
exports.USERAUTH_PK_OK = 60;
exports.USERAUTH_INFO_REQUEST = 60;
exports.USERAUTH_INFO_RESPONSE = 61;

var DISCONNECT_REASON = exports.DISCONNECT_REASON = {
  HOST_NOT_ALLOWED_TO_CONNECT: 1,
  PROTOCOL_ERROR: 2,
  KEY_EXCHANGE_FAILED: 3,
  RESERVED: 4,
  MAC_ERROR: 5,
  COMPRESSION_ERROR: 6,
  SERVICE_NOT_AVAILABLE: 7,
  PROTOCOL_VERSION_NOT_SUPPORTED: 8,
  HOST_KEY_NOT_VERIFIABLE: 9,
  CONNECTION_LOST: 10,
  BY_APPLICATION: 11,
  TOO_MANY_CONNECTIONS: 12,
  AUTH_CANCELED_BY_USER: 13,
  NO_MORE_AUTH_METHODS_AVAILABLE: 14,
  ILLEGAL_USER_NAME: 15
};
for (i=0,keys=Object.keys(DISCONNECT_REASON),len=keys.length; i<len; ++i)
  DISCONNECT_REASON[DISCONNECT_REASON[keys[i]]] = keys[i];

var CHAN_OPEN_FAILURE = exports.CHAN_OPEN_FAILURE = {
  ADMINISTRATIVELY_PROHIBITED: 1,
  CONNECT_FAILED: 2,
  UNKNOWN_CHANNEL_TYPE: 3,
  RESOURCE_SHORTAGE: 4
};
for (i=0,keys=Object.keys(CHAN_OPEN_FAILURE),len=keys.length; i<len; ++i)
  CHAN_OPEN_FAILURE[CHAN_OPEN_FAILURE[keys[i]]] = keys[i];

var TERMINAL_MODE = exports.TERMINAL_MODE = {
  OP_END: 0
};
for (i=0,keys=Object.keys(TERMINAL_MODE),len=keys.length; i<len; ++i)
  TERMINAL_MODE[TERMINAL_MODE[keys[i]]] = keys[i];

var CHAN_EXTEND_DATATYPE = exports.CHAN_EXTEND_DATATYPE = {
  STDERR: 1
};
for (i=0,keys=Object.keys(CHAN_EXTEND_DATATYPE),len=keys.length; i<len; ++i)
  CHAN_EXTEND_DATATYPE[CHAN_EXTEND_DATATYPE[keys[i]]] = keys[i];

var KEX = [
      'diffie-hellman-group1-sha1', // REQUIRED
      'diffie-hellman-group14-sha1' // REQUIRED
    ],
    KEX_LIST = new Buffer(KEX.join(',')),
    SERVER_HOST_KEY = [
      'ssh-rsa', // RECOMMENDED  sign   Raw RSA Key
      'ssh-dss'  // REQUIRED     sign   Raw DSS Key
    ],
    SERVER_HOST_KEY_LIST = new Buffer(SERVER_HOST_KEY.join(',')),
    CIPHER = [
      // from <http://tools.ietf.org/html/rfc4345#section-4>:
      /*'arcfour256',
      'arcfour128',

      'arcfour',     // OPTIONAL      the ARCFOUR stream cipher with a 128-bit key*/

      'aes128-cbc',  // RECOMMENDED   AES with a 128-bit key
      'aes192-cbc',  // OPTIONAL      AES with a 192-bit key
      'aes256-cbc',  // OPTIONAL      AES in CBC mode, with a 256-bit key

      // from <http://tools.ietf.org/html/rfc4344#section-4>:
      'aes128-ctr',  // RECOMMENDED   AES in SDCTR mode, with 128-bit key
      'aes192-ctr',  // RECOMMENDED   AES with 192-bit key
      'aes256-ctr',  // RECOMMENDED   AES with 256-bit key
      '3des-ctr',    // RECOMMENDED   Three-key 3DES in SDCTR mode

      '3des-cbc'     // REQUIRED      three-key 3DES in CBC mode
      //'none'       // OPTIONAL      no encryption; NOT RECOMMENDED
    ],
    CIPHER_LIST = new Buffer(CIPHER.join(',')),
    HMAC = [
      //'hmac-sha1-96',// RECOMMENDED   first 96 bits of HMAC-SHA1
                     //                (digest length = 12, key length = 20)
      'hmac-sha1',   // REQUIRED      HMAC-SHA1 (digest length = key length = 20)
      //'hmac-md5-96', // OPTIONAL      first 96 bits of HMAC-MD5
                     //                (digest length = 12, key length = 16)
      //'hmac-md5'     // OPTIONAL      HMAC-MD5 (digest length = key length = 16)
      'hmac-sha2-256',
      'hmac-sha2-256-96',
      'hmac-sha2-512',
      'hmac-sha2-512-96',
      'hmac-ripemd160'
      //'none'       // OPTIONAL      no MAC; NOT RECOMMENDED
    ],
    HMAC_LIST = new Buffer(HMAC.join(',')),
    COMPRESS = [
      'none'   // REQUIRED        no compression
      //'zlib' // OPTIONAL        ZLIB (LZ77) compression
    ],
    COMPRESS_LIST = new Buffer(COMPRESS.join(','));
var ALGORITHMS = exports.ALGORITHMS = {
  KEX: KEX,
  KEX_LIST: KEX_LIST,
  KEX_LIST_SIZE: KEX_LIST.length,
  SERVER_HOST_KEY: SERVER_HOST_KEY,
  SERVER_HOST_KEY_LIST: SERVER_HOST_KEY_LIST,
  SERVER_HOST_KEY_LIST_SIZE: SERVER_HOST_KEY_LIST.length,
  CIPHER: CIPHER,
  CIPHER_LIST: CIPHER_LIST,
  CIPHER_LIST_SIZE: CIPHER_LIST.length,
  HMAC: HMAC,
  HMAC_LIST: HMAC_LIST,
  HMAC_LIST_SIZE: HMAC_LIST.length,
  COMPRESS: COMPRESS,
  COMPRESS_LIST: COMPRESS_LIST,
  COMPRESS_LIST_SIZE: COMPRESS_LIST.length,
};
exports.SSH_TO_OPENSSL = {
  // ciphers
  '3des-cbc': 'des-ede3-cbc',
  'blowfish-cbc': 'bf-cbc',
  'aes256-cbc': 'aes-256-cbc',
  'aes192-cbc': 'aes-192-cbc',
  'aes128-cbc': 'aes-128-cbc',
  'idea-cbc': 'idea-cbc',
  'cast128-cbc': 'cast-cbc',
  'rijndael-cbc@lysator.liu.se': 'aes-256-cbc',
  'arcfour128': 'rc4',
  'arcfour256': 'rc4',
  'arcfour512': 'rc4',
  'arcfour': 'rc4',
  'camellia128-cbc': 'camellia-128-cbc',
  'camellia192-cbc': 'camellia-192-cbc',
  'camellia256-cbc': 'camellia-256-cbc',
  'camellia128-cbc@openssh.org': 'camellia-128-cbc',
  'camellia192-cbc@openssh.org': 'camellia-192-cbc',
  'camellia256-cbc@openssh.org': 'camellia-256-cbc',
  '3des-ctr': 'des-ede3',
  'blowfish-ctr': 'bf-ecb',
  'aes256-ctr': 'aes-256-ecb',
  'aes192-ctr': 'aes-192-ecb',
  'aes128-ctr': 'aes-128-ecb',
  'cast128-ctr': 'cast5-ecb',
  'camellia128-ctr': 'camellia-128-ecb',
  'camellia192-ctr': 'camellia-192-ecb',
  'camellia256-ctr': 'camellia-256-ecb',
  'camellia128-ctr@openssh.org': 'camellia-128-ecb',
  'camellia192-ctr@openssh.org': 'camellia-192-ecb',
  'camellia256-ctr@openssh.org': 'camellia-256-ecb',
  'none': 'none',
  // hmac
  'hmac-sha1-96': 'sha1',
  'hmac-sha1': 'sha1',
  'hmac-sha2-256': 'sha256',
  'hmac-sha2-256-96': 'sha256',
  'hmac-sha2-512': 'sha512',
  'hmac-sha2-512-96': 'sha512',
  'hmac-md5-96': 'md5',
  'hmac-md5': 'md5',
  'hmac-ripemd160': 'ripemd160'
};