/**
 * react-native mock for node-environment component tests (vitest aliases
 * `react-native` to this module).
 *
 * Primitives are transparent passthroughs: children render so the tree and
 * text content can be asserted, while every handler prop (onPress,
 * onChangeText, onValueChange, onSubmitEditing, onRefresh) stays reachable
 * on the instance for tests to invoke directly. Imperative APIs (Alert,
 * Share) are spies so tests can drive dialog button callbacks.
 */
import React, { Fragment } from "react";
import { vi } from "vitest";

type AnyProps = { children?: React.ReactNode; [key: string]: unknown };

function host(displayName: string): React.FC<AnyProps> {
  const C: React.FC<AnyProps> = ({ children }) =>
    children === null || children === undefined || children === false ? null : <Fragment>{children}</Fragment>;
  C.displayName = displayName;
  return C;
}

export const View = host("View");
export const Text = host("Text");
export const TextInput = host("TextInput");
export const TouchableOpacity = host("TouchableOpacity");
export const ScrollView = host("ScrollView");
export const ActivityIndicator = host("ActivityIndicator");
export const KeyboardAvoidingView = host("KeyboardAvoidingView");
export const RefreshControl = host("RefreshControl");
export const Switch = host("Switch");

/** FlatList renders every row synchronously (tests assert full lists —
 * the real component's virtualization windowing is native-side behavior
 * this node environment cannot exercise anyway). Header/footer ride as
 * children so tree queries keep working. E-9 (2026-09-21). */
type FlatListProps = {
  data: unknown[];
  renderItem: (info: { item: unknown }) => React.ReactElement;
  keyExtractor?: (item: unknown, index: number) => string;
  ListHeaderComponent?: React.ReactNode;
  ListFooterComponent?: React.ReactNode;
  children?: React.ReactNode;
  [key: string]: unknown;
};

const FlatListHost = host("FlatList");

export const FlatList: React.FC<FlatListProps> = ({
  data,
  renderItem,
  keyExtractor,
  ListHeaderComponent,
  ListFooterComponent,
  children,
  ...rest
}) => {
  const rows = data.map((item, index) => (
    <Fragment key={keyExtractor ? String(keyExtractor(item, index)) : String(index)}>
      {renderItem({ item })}
    </Fragment>
  ));
  return (
    <FlatListHost {...rest}>
      {children ?? (
        <>
          {ListHeaderComponent}
          {rows}
          {ListFooterComponent}
        </>
      )}
    </FlatListHost>
  );
};
FlatList.displayName = "FlatList";

export const StyleSheet = {
  create: <T,>(styles: T): T => styles,
  flatten: (...styles: unknown[]): Record<string, unknown> =>
    Object.assign({}, ...styles.filter((s): s is Record<string, unknown> => Boolean(s) && typeof s === "object")),
};

export const Platform = {
  OS: "ios" as const,
  // A modern device by default; tests that need an older system (e.g. the
  // healthkit iOS-18 capability gate) assign a different Version.
  Version: 18.5,
  select: <T,>(opts: { ios?: T; android?: T; native?: T; default?: T }): T =>
    opts.ios ?? opts.native ?? (opts.default as T),
};

export const Alert = { alert: vi.fn() };
export const Share = { share: vi.fn(async () => ({})) };

/** The theme system reads the OS scheme through this hook; tests default to
 *  the dark palette and override with mockReturnValue("light"). */
export const useColorScheme = vi.fn((): "dark" | "light" => "dark");

/** Keyboard.dismiss is the keyboard-dismiss affordance on the Entry screen. */
export const Keyboard = { dismiss: vi.fn() };

/** Vibration backs the light haptics (src/haptics.ts); captured for asserts. */
export const Vibration = { vibrate: vi.fn() };

/** BackHandler stub: HistoryScreen's Android hardware-back handling
 *  registers here; tests capture the subscription to fire it. */
export const BackHandler = {
  addEventListener: vi.fn((_event: string, _handler: () => boolean) => ({ remove: vi.fn() })),
  exitApp: vi.fn(),
};

/** AppState stub: listeners are captured so tests can fire background /
 *  inactive transitions and assert the vault auto-lock. */
export const AppState = {
  currentState: "active" as string,
  addEventListener: vi.fn((_type: string, _listener: (state: string) => void) => ({ remove: vi.fn() })),
};
