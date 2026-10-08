import jsQR from "jsqr";
import { expect, it } from "vitest";
import { act } from "react";
import { TotpQr } from "../src/TotpQr";
import { render } from "./helpers/rtr";

const uri = "otpauth://totp/Fathom:drportal?secret=JBSWY3DPEHPK3PXP&issuer=Fathom&algorithm=SHA1&digits=6&period=30";

it("renders an authenticator-scannable local QR code with an accessible label", async () => {
  const root = await render(<TotpQr uri={uri} />);
  const svg = root.root.findByType("svg");
  expect(svg.props.role).toBe("img");
  expect(svg.props["aria-label"]).toBe("Scan this QR code with your authenticator app");
  expect(svg.props.className).toBe("totp-qr");
  expect(svg.props.shapeRendering).toBe("crispEdges");
  expect(svg.props.width).toBe("224");
  expect(svg.props.height).toBe("224");
  const [, , width, height] = String(svg.props.viewBox).split(" ").map(Number);
  expect(width).toBe(height);
  const background = root.root.findByType("rect");
  expect(background.props.width).toBe(width);
  expect(background.props.height).toBe(height);
  expect(background.props.fill).toBe("#fff");
  const path = root.root.findByType("path");
  expect(path.props.fill).toBe("#000");
  // Rasterize the public SVG cell commands and decode with an independent
  // QR reader. The assertion is the enrolled URI, not generator-private bytes.
  const scale = 4;
  const edge = width! * scale;
  const pixels = new Uint8ClampedArray(edge * edge * 4).fill(255);
  const cells = String(path.props.d).matchAll(/M(\d+),(\d+)h1v1h-1z/g);
  for (const cell of cells) {
    const x = Number(cell[1]) * scale;
    const y = Number(cell[2]) * scale;
    for (let dy = 0; dy < scale; dy++) {
      for (let dx = 0; dx < scale; dx++) {
        const offset = ((y + dy) * edge + x + dx) * 4;
        pixels[offset] = pixels[offset + 1] = pixels[offset + 2] = 0;
      }
    }
  }
  expect(jsQR(pixels, edge, edge)?.data).toBe(uri);

  const replacement = "otpauth://totp/Fathom:other?secret=KRSXG5DSNFXGOIDB&issuer=Fathom";
  await act(async () => { root.update(<TotpQr uri={replacement} />); });
  const replacementWidth = Number(String(root.root.findByType("svg").props.viewBox).split(" ")[2]);
  const replacementEdge = replacementWidth * scale;
  const nextPixels = new Uint8ClampedArray(replacementEdge * replacementEdge * 4).fill(255);
  for (const cell of String(root.root.findByType("path").props.d).matchAll(/M(\d+),(\d+)h1v1h-1z/g)) {
    for (let dy = 0; dy < scale; dy++) for (let dx = 0; dx < scale; dx++) {
      const offset = ((Number(cell[2]) * scale + dy) * replacementEdge + Number(cell[1]) * scale + dx) * 4;
      nextPixels[offset] = nextPixels[offset + 1] = nextPixels[offset + 2] = 0;
    }
  }
  expect(jsQR(nextPixels, replacementEdge, replacementEdge)?.data).toBe(replacement);
});
