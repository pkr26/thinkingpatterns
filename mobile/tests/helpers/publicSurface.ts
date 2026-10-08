import React from "react";
import type { ReactTestInstance, ReactTestRenderer } from "react-test-renderer";

const nativeNames = new Set(["View", "Text", "TextInput", "TouchableOpacity", "ScrollView", "ActivityIndicator", "KeyboardAvoidingView", "RefreshControl", "Switch", "FlatList", "Pressable"]);
const nativeProps = new Set([
  "accessible", "accessibilityLabel", "accessibilityHint", "accessibilityRole", "accessibilityState", "accessibilityValue", "accessibilityLiveRegion", "accessibilityViewIsModal", "accessibilityElementsHidden", "importantForAccessibility",
  "style", "contentContainerStyle", "pointerEvents", "disabled", "editable", "value", "placeholder", "placeholderTextColor", "secureTextEntry", "keyboardType", "returnKeyType", "autoCapitalize", "autoCorrect", "autoComplete", "textContentType", "multiline", "maxLength", "blurOnSubmit",
  "selectable", "numberOfLines", "ellipsizeMode", "allowFontScaling", "maxFontSizeMultiplier", "color", "size", "refreshing", "tintColor", "colors", "title", "thumbColor", "trackColor", "scrollEnabled", "keyboardShouldPersistTaps", "keyboardDismissMode", "showsVerticalScrollIndicator", "refreshControl",
]);

function flattenedStyle(style: unknown): Record<string, unknown> {
  if (!style) return {};
  if (Array.isArray(style)) return Object.assign({}, ...style.map(flattenedStyle));
  return typeof style === "object" ? style as Record<string, unknown> : {};
}

function publicValue(value: unknown): unknown {
  if (typeof value === "number" && !Number.isFinite(value)) return { nativeNumber: String(value) };
  if (value === null || typeof value === "string" || typeof value === "number" || typeof value === "boolean") return value;
  if (Array.isArray(value)) return value.map(publicValue);
  if (React.isValidElement(value)) {
    const type = value.type as { displayName?: string };
    return nativeNames.has(type.displayName ?? "") ? { type: type.displayName, props: props(value.props as Record<string, unknown>) } : undefined;
  }
  if (typeof value === "object" && value) return Object.fromEntries(Object.entries(value).flatMap(([key, item]) => {
    const clean = publicValue(item);
    return clean === undefined ? [] : [[key, clean]];
  }));
  return undefined;
}

function props(input: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(Object.entries(input).flatMap(([key, value]) => {
    if (!nativeProps.has(key)) return [];
    const clean = publicValue(key === "style" || key === "contentContainerStyle" ? flattenedStyle(value) : value);
    return clean === undefined ? [] : [[key, clean]];
  }));
}

function children(node: ReactTestInstance | string): unknown[] {
  if (typeof node === "string") return [node];
  const type = node.type as { displayName?: string };
  const output = node.children.flatMap(child => children(child));
  if (!nativeNames.has(type.displayName ?? "")) return output;
  return [{ type: type.displayName, props: props(node.props as Record<string, unknown>), children: output }];
}

/** The native component inputs actually rendered in a scenario, including
 * merged styles and assistive-technology properties. Composite internals,
 * callbacks, generated identifiers and test-only props never enter it. */
export function publicSurface(renderer: ReactTestRenderer): unknown {
  try { return children(renderer.root); }
  catch { return null; } // A legitimately unmounted tree has no surface.
}
