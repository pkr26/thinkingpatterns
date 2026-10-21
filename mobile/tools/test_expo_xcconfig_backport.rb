require 'pathname'
require 'tmpdir'
require 'cocoapods'
require 'minitest/autorun'

module_path = if ARGV.first == '--module'
  ARGV.shift
  raise 'missing module path' if ARGV.empty?
  ARGV.shift
else
  File.expand_path('../node_modules/expo-modules-autolinking/scripts/ios/project_integrator.rb', __dir__)
end
load File.realpath(module_path)

class ExpoXcconfigBackportTest < Minitest::Test
  def setup
    @directory = Dir.mktmpdir('expo-xcconfig-regression-')
    @path = Pathname.new(@directory) + 'fixture.debug.xcconfig'
    @macro = '-Xfrontend -load-plugin-executable -Xfrontend "/private/Plugin#Plugin"'
    map = '"-fmodule-map-file=$(PODS_ROOT)/React-Core-prebuilt/Headers/module.modulemap"'
    @disk = {
      'HEADER_SEARCH_PATHS' => '$(inherited) "$(PODS_ROOT)/React-Core-prebuilt/Headers"',
      'OTHER_CFLAGS' => '$(inherited) ' + map,
      'OTHER_CPLUSPLUSFLAGS' => '$(inherited) -DRCT_NEW_ARCH_ENABLED=1 ' + map,
      'OTHER_SWIFT_FLAGS' => '$(inherited) -DRCT_NEW_ARCH_ENABLED -Xcc ' + map,
      'EXISTING_POST_INSTALL_SENTINEL' => 'preserved'
    }
    @memory = { 'OTHER_SWIFT_FLAGS' => '$(inherited) -DRCT_NEW_ARCH_ENABLED' }
    @settings = Struct.new(:xcconfig).new(Xcodeproj::Config.new(@memory))
  end

  def teardown
    FileUtils.remove_entry(@directory)
  end

  def append
    Expo::ProjectIntegrator.append_macro_flags(@settings, @path, @macro)
  end

  def test_preserves_all_post_install_edits_on_disk
    Xcodeproj::Config.new(@disk).save_as(@path)
    append
    expected = @disk.merge('OTHER_SWIFT_FLAGS' => @disk['OTHER_SWIFT_FLAGS'] + ' ' + @macro)
    assert_equal expected, Xcodeproj::Config.new(@path).attributes
  end

  def test_repeated_invocation_is_byte_idempotent
    Xcodeproj::Config.new(@disk).save_as(@path)
    append
    first = @path.binread
    append
    assert_equal first, @path.binread
    assert_equal 1, Xcodeproj::Config.new(@path).attributes['OTHER_SWIFT_FLAGS'].scan(@macro).length
  end

  def test_existing_macro_on_disk_keeps_every_byte
    Xcodeproj::Config.new(@disk.merge('OTHER_SWIFT_FLAGS' => @disk['OTHER_SWIFT_FLAGS'] + ' ' + @macro)).save_as(@path)
    first = @path.binread
    append
    assert_equal first, @path.binread
  end

  def test_absent_file_uses_existing_build_settings
    append
    assert_equal @memory['OTHER_SWIFT_FLAGS'] + ' ' + @macro, Xcodeproj::Config.new(@path).attributes['OTHER_SWIFT_FLAGS']
  end
end
