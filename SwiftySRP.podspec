Pod::Spec.new do |spec|
    spec.name         = 'SwiftySRP'
    spec.version      = '1.1'
    spec.ios.deployment_target = "9.0"
    spec.license      = { :type => 'MIT', :file => 'LICENSE' }
    spec.summary      = 'Swift implementation of SRP'
    spec.homepage     = 'https://github.com/serieuxchat/SwiftySRP'
    spec.author       = 'Sergey Novitsky'
    spec.source       = { :git => 'https://github.com/serieuxchat/SwiftySRP.git', :tag => 'v' + String(spec.version) }
    spec.source_files = 'SwiftySRP/*.swift'
    spec.documentation_url = 'https://github.com/serieuxchat/SwiftySRP/'
    spec.dependency 'BigInt', '~> 2.1'
    spec.preserve_paths = 'CommonCrypto/module.modulemap', 'imath/**', 'README', 'SwiftySRPTests/*.swift'
    spec.xcconfig = { 'SWIFT_INCLUDE_PATHS' => '$(PODS_ROOT)/SwiftySRP/CommonCrypto $(SRCROOT)/../CommonCrypto' }
    
    
end