Pod::Spec.new do |s|
  s.name         = "ObjectivePGP"
  s.version      = "0.4.1"
  s.summary      = "OpenPGP implementation for iOS and OSX"
  s.description  = "ObjectivePGP is OpenPGP implementation for iOS and OSX."
  s.homepage     = "https://krzyzanowskim@bitbucket.org/krzyzanowskim/objectivepgp.git"
  s.license	     = { :type => 'BSD', :file => 'LICENSE.txt' }
  s.source       = { :git => "https://github.com/krzyzanowskim/ObjectivePGP.git", :tag => "#{s.version}" }

  s.authors       =  {'Marcin Krzyżanowski' => 'marcin.krzyzanowski@hakore.com'}
  
  s.ios.platform          = :ios, '6.0'
  s.ios.deployment_target = '6.0'
  s.ios.header_dir          = 'ObjectivePGP'

  s.osx.platform          = :osx, '10.9'
  s.osx.deployment_target = '10.9'
  s.osx.header_dir          = 'ObjectivePGP'

  s.source_files = 'ObjectivePGP/*.{h,m}'
  s.public_header_files = 'ObjectivePGP/*.h'

  s.dependency 'OpenSSL-Universal', '>= 1.0.1.p'
  s.requires_arc = true

  s.libraries =  'z', 'bz2'
end
