# TODO: Bump this up to iOS9
platform :ios, '8.1'
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
      
      target 'SwiftySRPTestAppTests' do
      end
      
    end
end

