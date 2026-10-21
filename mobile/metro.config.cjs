/** Expo native defaults with the installed React Native polyfill provider. */
const { getDefaultConfig } = require("expo/metro-config");
const { getDefaultConfig: getReactNativeConfig } = require("@react-native/metro-config");

const config = getDefaultConfig(__dirname);
const getNativePolyfills = getReactNativeConfig(__dirname).serializer.getPolyfills;
// Expo SDK 57 references the wrapper removed in React Native 0.87.
config.serializer.getPolyfills = (options) =>
  options.platform ? getNativePolyfills(options) : [];

module.exports = config;
