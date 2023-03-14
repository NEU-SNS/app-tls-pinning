Java.perform(function () {

  try {
      var CertificatePinner = Java.use('okhttp3.CertificatePinner');
      CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function (str) {
          console.log('! Intercepted okhttp3: ' + str);
          return;
      };

      console.log('[X] Setup okhttp3 pinning')
  } catch(err) {
      console.log('! Unable to hook into okhttp3 pinner')
  }

  // Particularly for com.commbank.*
  try {
    var ICTSecurity = Java.use('com.ICTSecurity.KIA.KIAWhitelist');
    ICTSecurity.verifyCertificate.overload('java.lang.String', 'java.lang.String').implementation = function (str) {
      console.log('[X] Intercepted ICT Security:' + str);
      return true;
    };
  } catch(err) {
    console.log('! Error patching ICTSecurity.KIA');
    // console.log(err);
  }

  // https://neo-geo2.gitbook.io/adventures-on-security/frida/analysis-of-network-security-configuration-bypasses-with-frida#network-security-config-bypass-cr.js
  // Get around Network Security Configs
  try {
    var ANDROID_VERSION_M = 23;
    var DefaultConfigSource = Java.use("android.security.net.config.ManifestConfigSource$DefaultConfigSource");
    var NetworkSecurityConfig = Java.use("android.security.net.config.NetworkSecurityConfig");
    var ManifestConfigSource = Java.use("android.security.net.config.ManifestConfigSource");

    var NetworkSecurityTrustManager = Java.use("android.security.net.config.NetworkSecurityTrustManager");

    ManifestConfigSource.getConfigSource.implementation = function () {
      console.log("[+] Modifying ManifestConfigSource getConfigSource");
      //if the API is <= 25 the DefaultConfigSource has 2 methods, if not it has 3.
      if (DefaultConfigSource.$new.argumentTypes.length == 2) {
        return DefaultConfigSource.$new(true,ANDROID_VERSION_M);
      } else {
        return DefaultConfigSource.$new(true,ANDROID_VERSION_M,ANDROID_VERSION_M);
      }
    }
  } catch(err) {
    consol.log('! Error patching Network security config')
  }

});
