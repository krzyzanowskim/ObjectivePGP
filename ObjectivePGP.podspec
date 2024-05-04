Pod::Spec.new do |s|
  s.name         = "ObjectivePGP"
  s.version      = "1.0"
  s.summary      = "OpenPGP for iOS and macOS"
  s.description  = "Native OpenPGP (RFC 4880) implementation for iOS and macOS."
  s.homepage     = "http://objectivepgp.com"
  s.license	     = { :type => 'BSD for non-commercial use', :file => 'LICENSE.txt' }
  s.source       = { :git => "https://github.com/krzyzanowskim/ObjectivePGP.git", :tag => "#{s.version}" }

  s.authors      = {'Marcin Krzyzanowski' => 'marcin@krzyzanowskim.com'}
  s.social_media_url   = "https://twitter.com/krzyzanowskim"

  s.cocoapods_version = '>= 1.9'
  s.ios.deployment_target = '12.0'
  s.osx.deployment_target = '10.15'
  s.vendored_frameworks = 'Frameworks/ObjectivePGP.xcframework'

  s.pod_target_xcconfig = { 'OTHER_LDFLAGS' => '-lObjC' }

  s.weak_frameworks = 'Security'
  s.libraries =  'z', 'bz2'

  s.requires_arc = true
end
