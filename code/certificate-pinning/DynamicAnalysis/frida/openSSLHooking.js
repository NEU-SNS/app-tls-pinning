var HOOK_KEYLOG = true;
var HOOK_CLEANSE = false;
var HOOK_WRITE = true;
var HOOK_READ = true;
var PRINT_VERSION = true;

var callback_func = new NativeCallback(function (ssl, line) {
  console.log(line.readCString());
  return 0;
}, 'void', ['pointer', 'pointer']);

var hook = function(mod) {
  var module;
  var name = '';
  if (typeof mod === 'string' || mod instanceof String) {
    name = "lib" + mod + ".so";
    console.log("Looking for functions to hook in " + name + ".");
    module = Module.findModuleByName(name);
  } else {
    module = mod;
    name = mod.name;
  }

  if (name == "nss3")
    console.log("Found libnss3.so!");

  // OpenSSL
  if (PRINT_VERSION && module.findExportByName("SSLeay_version")) {
    var SSLeay_version_func = new NativeFunction(Module.findExportByName(name,"SSLeay_version"), 'pointer', ['int']);
    var version_string = SSLeay_version_func(0);
    var version_build_info = SSLeay_version_func(2);
    var version_dir_info = SSLeay_version_func(5);
    console.log("**** OpenSSL version info: ****");
    console.log(version_string.readCString());
    console.log(version_build_info.readCString());
    console.log(version_dir_info.readCString());
  }

  // OpenSSL
  if (PRINT_VERSION && module.findExportByName("OpenSSL_version")) {
    var OpenSSL_version_func = new NativeFunction(Module.findExportByName(name,"OpenSSL_version"), 'pointer', ['int']);
    var version_string = OpenSSL_version_func(0);
    var version_build_info = OpenSSL_version_func(2);
    var version_dir_info = OpenSSL_version_func(5);
    console.log("**** OpenSSL version info: ****");
    console.log(version_string.readCString());
    console.log(version_build_info.readCString());
    console.log(version_dir_info.readCString());
  }

  // NSS
  if (PRINT_VERSION && module.findExportByName("NSS_GetVersion")) {
    var NSS_GetVersion_func = new NativeFunction(Module.findExportByName(name,"NSS_GetVersion"), 'pointer', ['void']);
    var version_string = NSS_GetVersion_func();
    console.log("**** NSS version info: ****");
    console.log(version_string.readCString());
  }

  // OpenSSL
  if (HOOK_KEYLOG && module.findExportByName("SSL_new")) {
    console.log("SSL_new found in " + name + ", hooking!");

    Interceptor.attach(Module.findExportByName(name,"SSL_new"), {
      onEnter: function(args) {
        console.log("Hit SSL_new!");
        console.log("Hooking SSL_new with SSL_CTX_set_keylog_callback_func!");
        var SSL_CTX_set_keylog_callback_func = new NativeFunction(Module.findExportByName(name,"SSL_CTX_set_keylog_callback"), 'void', ['pointer', 'pointer']);
        console.log("Found the set function.");
        SSL_CTX_set_keylog_callback_func(args[0], callback_func);
        console.log("Called the set function.");
    }});
    console.log("Hooking successful.");
  }

  // OpenSSL
  if (HOOK_CLEANSE && module.findExportByName("OPENSSL_cleanse")) {
    console.log("OPENSSL_cleanse found in " + name + ", hooking!");

    Interceptor.attach(Module.findExportByName(name,"OPENSSL_cleanse"), {
      onEnter: function(args) {
        console.log("Hit OPENSSL_cleanse to clear a block of size " + args[1].toInt32());
        console.log(hexdump(args[0], {
                      offset: 0,
                      length: args[1].toInt32(),
                      header: false,
                      ansi: true
                    }));
    }});
    console.log("Hooking successful.");
  }

  // OpenSSL
  if (HOOK_WRITE && module.findExportByName("SSL_write")) {
    console.log("SSL_write found in " + name + ", hooking!");

    var SSL_get_servername_func = new NativeFunction(Module.findExportByName(name,"SSL_get_servername"), 'pointer', ['pointer', 'int']);
    var SSL_get_fd_func = new NativeFunction(Module.findExportByName(name,"SSL_get_fd"), 'int', ['pointer']);
    Interceptor.attach(Module.findExportByName(name,"SSL_write"), {
      onEnter: function(args) {
        var fd = SSL_get_fd_func(args[0]);
        var localAddress = Socket.localAddress(fd);
        var remoteAddress = Socket.peerAddress(fd);
        if (localAddress != null)
          console.log("FD info local: " + localAddress.ip + "-" + localAddress.port);
        if (remoteAddress != null)
          console.log("FD info remote: " + remoteAddress.ip + "-" + remoteAddress.port);

        var SNI = SSL_get_servername_func(args[0], 0);
        console.log("Hit SSL_write to send a block of size " + args[2].toInt32() + " SNI: " + SNI.readCString());
        console.log(hexdump(args[1], {
                      offset: 0,
                      length: args[2].toInt32(),
                      header: false,
                      ansi: true
                    }));
    }});
    console.log("Hooking successful.");
  }

  // OpenSSL
  if (HOOK_READ && module.findExportByName("SSL_read")) {
    console.log("SSL_read found in " + name + ", hooking!");

    var SSL_get_servername_func = new NativeFunction(Module.findExportByName(name,"SSL_get_servername"), 'pointer', ['pointer', 'int']);
    var SSL_get_fd_func = new NativeFunction(Module.findExportByName(name,"SSL_get_fd"), 'int', ['pointer']);
    Interceptor.attach(Module.findExportByName(name,"SSL_read"), {
      onEnter: function(args) {
        this.ssl = args[0];
        this.buf = args[1];
        this.buf_size = args[2].toInt32();
    },
      onLeave: function(retval) {
        var fd = SSL_get_fd_func(this.ssl);
        var localAddress = Socket.localAddress(fd);
        var remoteAddress = Socket.peerAddress(fd);
        if (localAddress != null)
          console.log("FD info local: " + localAddress.ip + "-" + localAddress.port);
        if (remoteAddress != null)
          console.log("FD info remote: " + remoteAddress.ip + "-" + remoteAddress.port);

        var SNI = SSL_get_servername_func(this.ssl, 0);
        console.log("Hit SSL_read to read a block of size " + retval.toInt32() + " SNI: " + SNI.readCString());
        if (retval.toInt32() > 0)
          console.log(hexdump(this.buf, {
                        offset: 0,
                        length: retval.toInt32(),
                        header: false,
                        ansi: true
                      }));
    }});
    console.log("Hooking successful.");
  }

  // NSS
  if (HOOK_WRITE && module.findExportByName("ssl_Send")) {
    console.log(modules[i].name.toString());
    console.log(" ** Has ssl_Send!");

    //var SSL_get_servername_func = new NativeFunction(modules[i].findExportByName("SSL_get_servername"), 'pointer', ['pointer', 'int']);
    //var SSL_get_fd_func = new NativeFunction(modules[i].findExportByName("SSL_get_fd"), 'int', ['pointer']);
    Interceptor.attach(module.findExportByName("ssl_Send"), {
      onEnter: function(args) {
        //var fd = SSL_get_fd_func(args[0]);
        //var localAddress = Socket.localAddress(fd);
        //var remoteAddress = Socket.peerAddress(fd);
        //console.log("FD info local: " + localAddress.ip + "-" + localAddress.port);
        //console.log("FD info remote: " + remoteAddress.ip + "-" + remoteAddress.port);

        //var SNI = SSL_get_servername_func(args[0], 0);
        // console.log("Hit SSL_write to send a block of size " + args[2].toInt32() + " SNI: " + SNI.readCString());
        console.log("Hit ssl_Send to send a block of size " + args[2].toInt32());
        console.log(hexdump(args[1], {
                      offset: 0,
                      length: args[2].toInt32(),
                      header: false,
                      ansi: true
                    }));
    }});
    console.log("Hooking successful.");
  }
}


var callback_func = new NativeCallback(function (ssl, line) {
	console.log(line.readCString());
	return 0;
}, 'void', ['pointer', 'pointer']);

var modules = Process.enumerateModules()
for (var i = 0; i < modules.length - 3; i += 1){
  //var exports = modules[i].enumerateExports();
  console.log(modules[i].name);
  hook(modules[i]);
}

Java.perform(function() {
    const System = Java.use('java.lang.System');
    const Runtime = Java.use('java.lang.Runtime');
    const SystemLoad_2 = System.loadLibrary.overload('java.lang.String');
    const VMStack = Java.use('dalvik.system.VMStack');

    System.loadLibrary.implementation = function(library) {
        try {
            console.log('System.loadLibrary("' + library + '")');
            const loaded = Runtime.getRuntime().loadLibrary0(VMStack.getCallingClassLoader(), library);
            hook(library);
            return loaded;
        } catch(ex) {
            console.log(ex);
        }
    };

    System.load.implementation = function(library) {
        try {
            console.log('System.load("' + library + '")');
            const loaded = Runtime.getRuntime().load0(VMStack.getCallingClassLoader(), library);
            hook(library);
            return loaded;
        } catch(ex) {
            console.log(ex);
        }
    };

    SystemLoad_2.implementation = function(library) {
        console.log('System.loadLibrary("' + library + '")');
        try {
            const loaded = Runtime.getRuntime().loadLibrary0(VMStack.getCallingClassLoader(), library);
            hook(library);
            return loaded;
        } catch(ex) {
            console.log(ex);
        }
    };

});

console.log("[*] Finished hooking.");
