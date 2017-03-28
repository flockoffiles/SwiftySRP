# TODO: Bump this up to iOS9
platform :ios, '9.0'
workspace 'SwiftySRP'

abstract_target 'SwiftySRP_Base' do
    use_frameworks!
    
    pod 'BigInt', '~> 2.1'
    
    target 'SwiftySRP' do
      project 'SwiftySRP'
      
      target 'SwiftySRPTests' do
      end
    end

    target 'SwiftySRPTestApp' do
        project 'SwiftySRPTestApp'
        pod 'SwiftySRP', :path => './SwiftySRP.podspec'

        target 'SwiftySRPTestAppTests' do
        end
        
    end

    target 'SwiftySRPPlayground' do
      project 'SwiftySRPPlayground'
      pod 'SwiftySRP', :path => './SwiftySRP.podspec'
    end
    
end

# This part is essential for playgrounds to work properly with frameworks installed with cocoapods.
post_install do |installer|
    installer.pods_project.targets.each do |target|
        target.build_configurations.each do |config|
            config.build_settings['CONFIGURATION_BUILD_DIR'] = '$PODS_CONFIGURATION_BUILD_DIR'
            if config.name == 'Debug'
                config.build_settings['OTHER_SWIFT_FLAGS'] = '-DDEBUG'
                else
                config.build_settings['OTHER_SWIFT_FLAGS'] = ''
            end
        end
    end
end
