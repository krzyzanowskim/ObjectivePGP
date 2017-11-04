#!/usr/bin/env ruby

require 'rubygems'
require 'xcodeproj'

project = Xcodeproj::Project.open("#{ARGV[0]}")
target = project.targets.first

filenames_public = target.headers_build_phase.files.select do |pbx_header_file|
  pbx_header_file.settings != nil && pbx_header_file.settings["ATTRIBUTES"].include?("Public")
end.select do |file|
  file.display_name != "#{target.product_name}.h" && file.display_name != "#{target.product_name}-Private.h"
end.map do |file|
  file.display_name
end

filenames_private = target.headers_build_phase.files.select do |pbx_header_file|
	pbx_header_file.settings != nil && pbx_header_file.settings["ATTRIBUTES"].include?("Private")
end.select do |file|
  file.display_name != "#{target.product_name}.h" && file.display_name != "#{target.product_name}-Private.h"
end.map do |file|
  file.display_name
end

header = <<MEND
//
//  #{target.name}
//
//  Copyright © Marcin Krzyżanowski. All rights reserved.
//
//  DO NOT MODIFY. FILE GENERATED AUTOMATICALLY.

#import <Foundation/Foundation.h>

//! Project version number for #{target.product_name}.
FOUNDATION_EXPORT double #{target.product_name}VersionNumber;

//! Project version string for #{target.product_name}.
FOUNDATION_EXPORT const unsigned char #{target.product_name}VersionString[];

MEND

File.open('ObjectivePGP/ObjectivePGP.h', 'w') do |f|
  f.puts header
  filenames_public.each do |filename|
    f.puts "#import <#{target.product_name}/#{filename}>"
  end
end

File.open('ObjectivePGP/ObjectivePGP-Private.h', 'w') do |f|
  f.puts header
  filenames_private.each do |filename|
    f.puts "#import <#{target.product_name}/#{filename}>"
  end
end
