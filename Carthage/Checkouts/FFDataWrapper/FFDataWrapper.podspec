Pod::Spec.new do |spec|
    spec.name         = 'FFDataWrapper'
    spec.version      = '1.0'
    spec.ios.deployment_target = "9.0"
    spec.license      = { :type => 'MIT', :file => 'LICENSE' }
    spec.summary      = 'Wrapper for data or string objects with custom internal storage'
    spec.homepage     = 'https://github.com/flockoffiles/FFDataWrapper'
    spec.author       = 'Sergey Novitsky'
    spec.source       = { :git => 'https://github.com/flockoffiles/FFDataWrapper.git', :tag => 'v' + String(spec.version) }
    spec.source_files = 'FFDataWrapper/*.swift',
	spec.public_header_files = 'FFDataWrapper/*.h'
    spec.documentation_url = 'https://github.com/flockoffiles/FFDataWrapper/'
    # spec.dependency '', '~> 0.0.0'
    spec.preserve_paths = 'README.md', 'FFDataWrapperTests/*.swift'
end