Pod::Spec.new do |spec|
    spec.name         = 'SwiftySRP'
    spec.version      = '2.3'
    spec.ios.deployment_target = "9.3"
    spec.license      = { :type => 'MIT', :file => 'LICENSE' }
    spec.summary      = 'Swift implementation of SRP'
    spec.homepage     = 'https://github.com/flockoffiles/SwiftySRP'
    spec.author       = 'Sergey Novitsky'
    spec.source       = { :git => 'https://github.com/flockoffiles/SwiftySRP.git', :tag => 'v' + String(spec.version) }
    spec.source_files = 'SwiftySRP/*.{h,swift}', 'imath/*.{c,h}'
    spec.exclude_files = 'SwiftySRP/BigIntSpecific/*'
    spec.public_header_files = 'SwiftySRP/**/*.h'
    spec.documentation_url = 'https://github.com/serieuxchat/SwiftySRP/'
    spec.dependency 'FFDataWrapper', '~> 1.3'
    spec.preserve_paths = 'CommonCrypto/module.modulemap', 'imath/**', 'README', 'SwiftySRPTests/*.swift'

    # Things are listed twice (with different paths) in order to also make it compile as a development pod.
    spec.xcconfig = { 'SWIFT_INCLUDE_PATHS' => '$(PODS_ROOT)/SwiftySRP/CommonCrypto $(PODS_ROOT)/SwiftySRP/imath $(SRCROOT)/../CommonCrypto $(SRCROOT)/../imath' }
end