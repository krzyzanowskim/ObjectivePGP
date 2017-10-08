#!/usr/bin/env ruby

require 'rubygems'
require 'xcodeproj'

project = Xcodeproj::Project.open("#{ARGV[0]}")
target = project.targets.first

filenames = target.headers_build_phase.files.select do |pbx_header_file|
	pbx_header_file.settings["ATTRIBUTES"].include?("Public")
end.select do |file|
  file.display_name != "#{target.product_name}.h"
end.map do |file|
  file.display_name
end

puts <<MEND
//
//  #{target.name}
//
//  Copyright © Marcin Krzyżanowski. All rights reserved.
//

#import <Foundation/Foundation.h>

//! Project version number for #{target.product_name}.
FOUNDATION_EXPORT double #{target.product_name}VersionNumber;

//! Project version string for #{target.product_name}.
FOUNDATION_EXPORT const unsigned char #{target.product_name}VersionString[];

MEND

filenames.each do |filename|
  puts "#import <#{target.product_name}/#{filename}>"
end