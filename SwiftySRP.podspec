Pod::Spec.new do |spec|
    spec.name         = 'SwiftySRP'
    spec.version      = '2.12'
    spec.ios.deployment_target = "9.3"
    spec.license      = { :type => 'MIT', :file => 'LICENSE' }
    spec.summary      = 'Swift implementation of SRP'
    spec.homepage     = 'https://github.com/flockoffiles/SwiftySRP'
    spec.author       = 'Sergey Novitsky'
    spec.source       = { :git => 'https://github.com/flockoffiles/SwiftySRP.git', :tag => 'v' + String(spec.version) }
    spec.source_files = 'SwiftySRP/*.{h,swift}', 'imath/*.{c,h}'
    spec.module_map = 'SwiftySRP/module.modulemap'
    spec.exclude_files = 'SwiftySRP/BigIntSpecific/*'
    spec.public_header_files = 'SwiftySRP/**/*.h' 
    spec.private_header_files = 'imath/*.h'
    spec.documentation_url = 'https://github.com/serieuxchat/SwiftySRP/'
    spec.dependency 'FFDataWrapper', '~> 1.8'
    spec.swift_version = '4.2'

    # Things are listed twice (with different paths) in order to also make it compile as a development pod.

    spec.preserve_paths = 'README', 'SwiftySRPTests/*.swift'

end
