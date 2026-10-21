/** actual App/Login/Settings and UI.
 * Copy into a disposable web/tests lane, never the frozen baseline tree.
 * Server/storage/native locks use the existing Node test seams; no view,
 * language subscriber, shell state setter or navigation component is mocked.
 */


import { act } from "react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { App } from "../src/App";
import { hasSession, sessionUserId } from "../src/api/client";
import { applyLanguagePref, getLocale, loadFullCatalogs } from "../src/strings";
import { vault } from "../src/vault";
import { jsonResponse, resetTestState, stubFetch } from "./helpers/api";
import { buttonByLabel, flush, press, render, textOf, textOfNode, typeInto } from "./helpers/rtr";

const OWNER = "0123456789abcdef0123456789abcdef";
const NAME = "synthetic_locale_patient";

async function producerCompletion(label: string, ready: () => boolean): Promise<void> {
  const deadline = Date.now() + 15_000;
  while (!ready()) {
    if (Date.now() >= deadline) throw new Error(`ExecutionError: producer completion timed out: ${label}`);
    await act(async () => { await new Promise<void>((resolve) => setTimeout(resolve, 10)); });
  }
  await flush();
}

beforeEach(() => { vi.useRealTimers(); resetTestState(); applyLanguagePref("en"); });
afterEach(() => { resetTestState(); vi.unstubAllGlobals(); applyLanguagePref("en"); });

it("repeated actual Settings language choices refresh both navigation surfaces and overflow labels", async () => {

  const check = (assertion: () => void): void => {
    { assertion();  }
  };
  try {
    // A supported warm-catalog session: after the first locale visit both
    // modules are cached. No late module completion may mask a broken tick.
    await Promise.all([loadFullCatalogs("en"), loadFullCatalogs("es")]);
    const apiCalls: string[] = [];
    stubFetch((url) => {
      apiCalls.push(url);
      if (url.endsWith("/auth/salt")) return jsonResponse({ salt: "AAECAwQFBgcICQoLDA0ODw==" });
      if (url.endsWith("/auth/login")) return jsonResponse({ token: "synthetic-locale-token", user_id: OWNER, expires_in: 86_400, role: "user" });
      return jsonResponse({ detail: "synthetic fixture endpoint unavailable", code: "not_found" }, { status: 404 });
    });
    const root = await render(<App />);
    await producerCompletion("real App boot", () => buttonByLabel(root, "Sign in"));
    await typeInto(root, "Username", NAME);
    await typeInto(root, "Password", "correct horse battery staple");
    await act(async () => { root.root.findByType("form").props.onSubmit({ preventDefault() {} }); });
    await producerCompletion("real Login adopts and actual App publishes onboarding", () => textOf(root).includes("Step 1 of 3"));
    await press(root, "Next"); await press(root, "Next"); await press(root, "Start journaling");
    await producerCompletion("actual journal chunk", () => textOf(root).includes("Today's entry"));
    await press(root, "More"); await press(root, "Settings");
    await producerCompletion("actual Settings language picker", () => root.root.findAllByProps({ role: "radiogroup", "aria-label": "Language" }).length === 1);
    // Settle the ordinary initial metadata reads before observing choices;
    // their mutations belong to Settings, not the App language subscriber.
    await flush(30);
    const originalKeys = vault.get();
    check(() => {
      expect(hasSession()).toBe(true); expect(sessionUserId()).toBe(OWNER);
      expect(vault.ownerUserId()).toBe(OWNER);
      expect(apiCalls.filter(url => url.endsWith("/auth/login"))).toHaveLength(1);
    });
    const observe = (locale: "en" | "es") => {
      const tabs = root.root.findAllByType("nav").find(node => node.props.className === "nav-tabs");
      const bottom = root.root.findAllByType("nav").find(node => node.props.className === "bottom-nav");
      const triggers = root.root.findAllByType("button").filter(node => node.props["aria-haspopup"] === "menu");
      const menus = root.root.findAllByProps({ role: "menu" });
      const row = {
        locale, actualLocale: getLocale(), tabs: tabs?.findAllByType("button").map(textOfNode),
        bottom: bottom?.findAllByType("button").map(textOfNode), moreTriggers: triggers.map(textOfNode),
        overflow: menus.flatMap(menu => menu.findAllByProps({ role: "menuitem" }).map(textOfNode)),
        picker: root.root.findAllByProps({ role: "radiogroup" }).filter(node => ["Language", "Idioma"].includes(node.props["aria-label"])).map(node => ({ label: node.props["aria-label"], selected: node.findAllByProps({ role: "radio", "aria-checked": true }).map(textOfNode) })),
      };

      return row;
    };
    for (const locale of ["es", "en", "es", "en"] as const) {
      const group = root.root.findAllByProps({ role: "radiogroup" }).find(node => ["Language", "Idioma"].includes(node.props["aria-label"]));
      const label = locale === "es" ? "Español" : "English";
      const radio = group?.findAllByProps({ role: "radio" }).find(node => textOfNode(node) === label);
      check(() => { expect(radio).toBeDefined(); expect(typeof radio?.props.onClick).toBe("function"); });
      await act(async () => { radio!.props.onClick(); });
      await flush();
      const primary = locale === "es" ? ["Hoy", "Historial", "Patrones", "Pregunta"] : ["Today", "History", "Patterns", "Question"];
      const more = locale === "es" ? "Más" : "More";

      const beforeOpen = observe(locale);
      {

{
 expect(beforeOpen.tabs).toEqual(primary);

}
}
      {

{
 expect(beforeOpen.bottom).toEqual([...primary, more]);

}
}
      {

{
 expect(beforeOpen.moreTriggers).toEqual([more, more]);

}
}
      // Opening only this child menu does not set any App state. Its item
      // strings must already come from the latest App-rendered props.
      await press(root, more);
      const afterOpen = observe(locale);
      {

{

        expect(afterOpen.overflow).toContain(locale === "es" ? "Ajustes" : "Settings");
        expect(afterOpen.overflow).toContain(locale === "es" ? "Compartir" : "Share");
        expect(afterOpen.overflow).toContain(locale === "es" ? "Privacidad" : "Privacy");


}
}
      {

{

        expect(afterOpen.actualLocale).toBe(locale);
        expect(afterOpen.picker).toEqual([{ label: locale === "es" ? "Idioma" : "Language", selected: [label] }]);
        expect(hasSession()).toBe(true); expect(vault.ownerUserId()).toBe(OWNER);
        expect(vault.get().authKey).toBe(originalKeys.authKey); expect(vault.get().dataKey).toBe(originalKeys.dataKey);


}
}
      await press(root, more); // Close only the child menu before next choice.
    }
    check(() => {
      expect(apiCalls.filter(url => url.endsWith("/auth/login"))).toHaveLength(1);
      expect(buttonByLabel(root, "Sign in")).toBe(false);
    });

  }
  finally {


  }
});
