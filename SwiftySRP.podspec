Pod::Spec.new do |spec|
    spec.name         = 'SwiftySRP'
    spec.version      = '4.0'
    spec.ios.deployment_target = "9.3"
    spec.license      = { :type => 'MIT', :file => 'LICENSE' }
    spec.summary      = 'Swift implementation of SRP'
    spec.homepage     = 'https://github.com/flockoffiles/SwiftySRP'
    spec.author       = 'Sergey Novitsky'
    spec.source       = { :git => 'https://github.com/flockoffiles/SwiftySRP.git', :tag => 'v' + String(spec.version) }
    spec.source_files = 'SwiftySRP/*.{h,swift}', 'imath/*.{c,h}'
    spec.public_header_files = 'SwiftySRP/**/*.h'
    spec.private_header_files = 'imath/*.h'
    spec.documentation_url = 'https://github.com/flockoffiles/SwiftySRP/'
    spec.swift_version = '5.0'
    spec.preserve_paths = 'README', 'SwiftySRPTests/*.swift'

end
