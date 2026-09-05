/**
 * @react-navigation/native-stack mock (vitest alias). Navigator renders its
 * Screen children transparently; Screen renders the component it was given
 * with a stub navigation prop, so navigator branch tests exercise the real
 * screen components without a native navigation container.
 */
import React from "react";
import { vi } from "vitest";

export const navigationStub = {
  navigate: vi.fn(),
  popToTop: vi.fn(),
};

export function createNativeStackNavigator() {
  const Navigator = ({ children }: { children?: React.ReactNode }) => <>{children}</>;
  const Screen = ({ component }: { component?: React.ComponentType<{ navigation: unknown }> }) =>
    component ? React.createElement(component, { navigation: navigationStub }) : null;
  return { Navigator, Screen };
}
