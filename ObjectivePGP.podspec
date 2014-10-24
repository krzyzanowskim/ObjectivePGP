Pod::Spec.new do |s|
  s.name         = "ObjectivePGP"
  s.version      = "0.3"
  s.summary      = "OpenPGP implementation for iOS and OSX"
  s.description  = "ObjectivePGP is OpenPGP implementation for iOS and OSX."
  s.homepage     = "https://github.com/krzyzanowskim/ObjectivePGP"
  s.license	     = { :type => 'Attribution License', :file => 'LICENSE.txt' }
  s.source       = { :git => "https://github.com/krzyzanowskim/ObjectivePGP.git", :tag => "#{s.version}" }

  s.authors       =  {'Marcin Krzyżanowski' => 'marcin.krzyzanowski@hakore.com'}
  
  s.ios.platform          = :ios, '6.0'
  s.ios.deployment_target = '6.0'
  s.ios.source_files        = 'lib-ios/include/ObjectivePGP/**/*.h'
  s.ios.public_header_files = 'lib-ios/include/ObjectivePGP/**/*.h'
  s.ios.header_dir          = 'ObjectivePGP'
  s.ios.preserve_paths      = 'lib-ios/libObjectivePGP.a'
  s.ios.vendored_libraries  = 'lib-ios/libObjectivePGP.a'

  s.osx.platform          = :osx, '10.9'
  s.osx.deployment_target = '10.9'
  s.osx.source_files        = 'lib-osx/include/ObjectivePGP/**/*.h'
  s.osx.public_header_files = 'lib-osx/include/ObjectivePGP/**/*.h'
  s.osx.header_dir          = 'ObjectivePGP'
  s.osx.preserve_paths      = 'lib-osx/libObjectivePGP.a'
  s.osx.vendored_libraries  = 'lib-osx/libObjectivePGP.a'

  s.libraries = 'ObjectivePGP', 'z', 'bz2'
end
