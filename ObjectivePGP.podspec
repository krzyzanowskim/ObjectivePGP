Pod::Spec.new do |s|
  s.name         = "ObjectivePGP"
  s.version      = "0.6"
  s.summary      = "OpenPGP for iOS and macOS"
  s.description  = "Native OpenPGP (RFC 4880) implementation for iOS and macOS."
  s.homepage     = "https://krzyzanowskim@bitbucket.org/krzyzanowskim/objectivepgp.git"
  s.license	     = { :type => 'BSD', :file => 'LICENSE.txt' }
  s.source       = { :git => "https://github.com/krzyzanowskim/ObjectivePGP.git", :tag => "#{s.version}" }

  s.authors      = {'Marcin Krzyżanowski' => 'marcin@krzyzanowskim.com'}
  s.social_media_url   = "https://twitter.com/krzyzanowskim"
  
  s.ios.deployment_target = '8.0'
  s.ios.header_dir          = 'ObjectivePGP'

  s.osx.deployment_target = '10.9'
  s.osx.header_dir          = 'ObjectivePGP'

  s.source_files = 'ObjectivePGP/**/*.{h,m}'
  s.public_header_files = 'ObjectivePGP/**/*.h'
    
  s.module_name  = "ObjectivePGP"

  s.framework    = 'Security'
  s.requires_arc = true

  s.libraries =  'z', 'bz2'
  s.dependency 'OpenSSL-Universal'
end
