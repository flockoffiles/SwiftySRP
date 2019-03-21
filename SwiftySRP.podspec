Pod::Spec.new do |spec|
    spec.name         = 'SwiftySRP'
    spec.version      = '2.9'
    spec.ios.deployment_target = "9.3"
    spec.license      = { :type => 'MIT', :file => 'LICENSE' }
    spec.summary      = 'Swift implementation of SRP'
    spec.homepage     = 'https://github.com/flockoffiles/SwiftySRP'
    spec.author       = 'Sergey Novitsky'
    spec.source       = { :git => 'https://github.com/flockoffiles/SwiftySRP.git', :tag => 'v' + String(spec.version) }
    spec.source_files = 'SwiftySRP/*.{h,swift}', 'imath/*.{c,h}'
    spec.module_map = 'SwiftySRP/private.modulemap'
    spec.exclude_files = 'SwiftySRP/BigIntSpecific/*'
    spec.public_header_files = 'SwiftySRP/**/*.h' 
    spec.private_header_files = 'imath/*.h'
    spec.documentation_url = 'https://github.com/serieuxchat/SwiftySRP/'
    spec.dependency 'FFDataWrapper', '~> 1.6'
    spec.swift_version = '4.1'
    spec.script_phases = [
        { :name => 'Fix Module Map', :script => 'rm -rf "$TARGET_BUILD_DIR/$PRODUCT_NAME$WRAPPER_SUFFIX/PrivateHeaders" ; function replace() { export SEARCH="$1" && export REPLACE="$2" && ruby -p -i -e "gsub(ENV[\"SEARCH\"], ENV[\"REPLACE\"])" "$3" ; } ; replace "header \"imath.h\"" "" "${TARGET_BUILD_DIR}/${PRODUCT_NAME}${WRAPPER_SUFFIX}/Modules/module.modulemap" ; replace "header \"imath+additions.h\"" "" "${TARGET_BUILD_DIR}/${PRODUCT_NAME}${WRAPPER_SUFFIX}/Modules/module.modulemap"' }
    ]

    # Things are listed twice (with different paths) in order to also make it compile as a development pod.

    spec.preserve_paths = 'Scripts/*.sh', 'README', 'SwiftySRPTests/*.swift', 'SwiftySRP/public.modulemap'

end
