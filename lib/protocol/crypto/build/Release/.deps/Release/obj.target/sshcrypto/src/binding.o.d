cmd_Release/obj.target/sshcrypto/src/binding.o := c++ -o Release/obj.target/sshcrypto/src/binding.o ../src/binding.cc '-DNODE_GYP_MODULE_NAME=sshcrypto' '-DUSING_UV_SHARED=1' '-DUSING_V8_SHARED=1' '-DV8_DEPRECATION_WARNINGS=1' '-DV8_DEPRECATION_WARNINGS' '-DV8_IMMINENT_DEPRECATION_WARNINGS' '-D_GLIBCXX_USE_CXX11_ABI=1' '-D_DARWIN_USE_64_BIT_INODE=1' '-D_LARGEFILE_SOURCE' '-D_FILE_OFFSET_BITS=64' '-DOPENSSL_API_COMPAT=0x10100000L' '-DREAL_OPENSSL_MAJOR=3' '-DBUILDING_NODE_EXTENSION' -I/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node -I/Users/alaptop/Library/Caches/node-gyp/18.19.1/src -I/Users/alaptop/Library/Caches/node-gyp/18.19.1/deps/openssl/config -I/Users/alaptop/Library/Caches/node-gyp/18.19.1/deps/openssl/openssl/include -I/Users/alaptop/Library/Caches/node-gyp/18.19.1/deps/uv/include -I/Users/alaptop/Library/Caches/node-gyp/18.19.1/deps/zlib -I/Users/alaptop/Library/Caches/node-gyp/18.19.1/deps/v8/include -I../../../../node_modules/.pnpm/nan@2.20.0/node_modules/nan  -O3 -gdwarf-2 -mmacosx-version-min=10.15 -arch arm64 -Wall -Wendif-labels -W -Wno-unused-parameter -std=gnu++17 -stdlib=libc++ -fno-rtti -fno-exceptions -fno-strict-aliasing -MMD -MF ./Release/.deps/Release/obj.target/sshcrypto/src/binding.o.d.raw   -c
Release/obj.target/sshcrypto/src/binding.o: ../src/binding.cc \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/node.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/cppgc/common.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8config.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-array-buffer.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-local-handle.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-internal.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-version.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-object.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-maybe.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-persistent-handle.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-weak-callback-info.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-primitive.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-data.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-value.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-traced-handle.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-container.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-context.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-snapshot.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-date.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-debug.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-script.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-message.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-exception.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-extension.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-external.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-function.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-function-callback.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-template.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-memory-span.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-initialization.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-callbacks.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-isolate.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-embedder-heap.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-microtask.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-statistics.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-promise.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-unwinder.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-embedder-state-scope.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-platform.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-json.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-locker.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-microtask-queue.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-primitive-object.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-proxy.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-regexp.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-typed-array.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-value-serializer.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-wasm.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/node_version.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/node_api.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/js_native_api.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/js_native_api_types.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/node_api_types.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/node_buffer.h \
  ../../../../node_modules/.pnpm/nan@2.20.0/node_modules/nan/nan.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/uv.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/uv/errno.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/uv/version.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/uv/unix.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/uv/threadpool.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/uv/darwin.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/node_object_wrap.h \
  ../../../../node_modules/.pnpm/nan@2.20.0/node_modules/nan/nan_callbacks.h \
  ../../../../node_modules/.pnpm/nan@2.20.0/node_modules/nan/nan_callbacks_12_inl.h \
  ../../../../node_modules/.pnpm/nan@2.20.0/node_modules/nan/nan_maybe_43_inl.h \
  ../../../../node_modules/.pnpm/nan@2.20.0/node_modules/nan/nan_converters.h \
  ../../../../node_modules/.pnpm/nan@2.20.0/node_modules/nan/nan_converters_43_inl.h \
  ../../../../node_modules/.pnpm/nan@2.20.0/node_modules/nan/nan_new.h \
  ../../../../node_modules/.pnpm/nan@2.20.0/node_modules/nan/nan_implementation_12_inl.h \
  ../../../../node_modules/.pnpm/nan@2.20.0/node_modules/nan/nan_persistent_12_inl.h \
  ../../../../node_modules/.pnpm/nan@2.20.0/node_modules/nan/nan_weak.h \
  ../../../../node_modules/.pnpm/nan@2.20.0/node_modules/nan/nan_object_wrap.h \
  ../../../../node_modules/.pnpm/nan@2.20.0/node_modules/nan/nan_private.h \
  ../../../../node_modules/.pnpm/nan@2.20.0/node_modules/nan/nan_typedarray_contents.h \
  ../../../../node_modules/.pnpm/nan@2.20.0/node_modules/nan/nan_json.h \
  ../../../../node_modules/.pnpm/nan@2.20.0/node_modules/nan/nan_scriptorigin.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/configuration.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/./configuration_asm.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/./archs/darwin64-arm64-cc/asm/include/openssl/configuration.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/err.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/./err_asm.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/./archs/darwin64-arm64-cc/asm/include/openssl/err.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/macros.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/opensslconf.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/opensslv.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/./opensslv_asm.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/./archs/darwin64-arm64-cc/asm/include/openssl/opensslv.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/e_os2.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/types.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/safestack.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/./safestack_asm.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/./archs/darwin64-arm64-cc/asm/include/openssl/safestack.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/stack.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/bio.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/./bio_asm.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/./archs/darwin64-arm64-cc/asm/include/openssl/bio.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/crypto.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/./crypto_asm.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/./archs/darwin64-arm64-cc/asm/include/openssl/crypto.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/cryptoerr.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/symhacks.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/cryptoerr_legacy.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/core.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/bioerr.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/lhash.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/./lhash_asm.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/./archs/darwin64-arm64-cc/asm/include/openssl/lhash.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/evp.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/core_dispatch.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/evperr.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/params.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/bn.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/bnerr.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/objects.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/obj_mac.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/asn1.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/./asn1_asm.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/./archs/darwin64-arm64-cc/asm/include/openssl/asn1.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/asn1err.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/objectserr.h \
  /Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/hmac.h
../src/binding.cc:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/node.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/cppgc/common.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8config.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-array-buffer.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-local-handle.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-internal.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-version.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-object.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-maybe.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-persistent-handle.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-weak-callback-info.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-primitive.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-data.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-value.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-traced-handle.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-container.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-context.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-snapshot.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-date.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-debug.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-script.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-message.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-exception.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-extension.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-external.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-function.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-function-callback.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-template.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-memory-span.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-initialization.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-callbacks.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-isolate.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-embedder-heap.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-microtask.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-statistics.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-promise.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-unwinder.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-embedder-state-scope.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-platform.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-json.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-locker.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-microtask-queue.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-primitive-object.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-proxy.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-regexp.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-typed-array.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-value-serializer.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/v8-wasm.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/node_version.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/node_api.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/js_native_api.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/js_native_api_types.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/node_api_types.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/node_buffer.h:
../../../../node_modules/.pnpm/nan@2.20.0/node_modules/nan/nan.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/uv.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/uv/errno.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/uv/version.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/uv/unix.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/uv/threadpool.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/uv/darwin.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/node_object_wrap.h:
../../../../node_modules/.pnpm/nan@2.20.0/node_modules/nan/nan_callbacks.h:
../../../../node_modules/.pnpm/nan@2.20.0/node_modules/nan/nan_callbacks_12_inl.h:
../../../../node_modules/.pnpm/nan@2.20.0/node_modules/nan/nan_maybe_43_inl.h:
../../../../node_modules/.pnpm/nan@2.20.0/node_modules/nan/nan_converters.h:
../../../../node_modules/.pnpm/nan@2.20.0/node_modules/nan/nan_converters_43_inl.h:
../../../../node_modules/.pnpm/nan@2.20.0/node_modules/nan/nan_new.h:
../../../../node_modules/.pnpm/nan@2.20.0/node_modules/nan/nan_implementation_12_inl.h:
../../../../node_modules/.pnpm/nan@2.20.0/node_modules/nan/nan_persistent_12_inl.h:
../../../../node_modules/.pnpm/nan@2.20.0/node_modules/nan/nan_weak.h:
../../../../node_modules/.pnpm/nan@2.20.0/node_modules/nan/nan_object_wrap.h:
../../../../node_modules/.pnpm/nan@2.20.0/node_modules/nan/nan_private.h:
../../../../node_modules/.pnpm/nan@2.20.0/node_modules/nan/nan_typedarray_contents.h:
../../../../node_modules/.pnpm/nan@2.20.0/node_modules/nan/nan_json.h:
../../../../node_modules/.pnpm/nan@2.20.0/node_modules/nan/nan_scriptorigin.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/configuration.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/./configuration_asm.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/./archs/darwin64-arm64-cc/asm/include/openssl/configuration.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/err.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/./err_asm.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/./archs/darwin64-arm64-cc/asm/include/openssl/err.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/macros.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/opensslconf.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/opensslv.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/./opensslv_asm.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/./archs/darwin64-arm64-cc/asm/include/openssl/opensslv.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/e_os2.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/types.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/safestack.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/./safestack_asm.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/./archs/darwin64-arm64-cc/asm/include/openssl/safestack.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/stack.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/bio.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/./bio_asm.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/./archs/darwin64-arm64-cc/asm/include/openssl/bio.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/crypto.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/./crypto_asm.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/./archs/darwin64-arm64-cc/asm/include/openssl/crypto.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/cryptoerr.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/symhacks.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/cryptoerr_legacy.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/core.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/bioerr.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/lhash.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/./lhash_asm.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/./archs/darwin64-arm64-cc/asm/include/openssl/lhash.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/evp.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/core_dispatch.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/evperr.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/params.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/bn.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/bnerr.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/objects.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/obj_mac.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/asn1.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/./asn1_asm.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/./archs/darwin64-arm64-cc/asm/include/openssl/asn1.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/asn1err.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/objectserr.h:
/Users/alaptop/Library/Caches/node-gyp/18.19.1/include/node/openssl/hmac.h:
