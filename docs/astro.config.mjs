// @ts-check
import { defineConfig } from "astro/config";
import starlight from "@astrojs/starlight";
import starlightThemeFlexoki from "starlight-theme-flexoki";
import mermaid from "astro-mermaid";

// https://astro.build/config
export default defineConfig({
  site: "https://sotnii.github.io",
  base: "/pakostii",
  integrations: [
    mermaid({
      theme: "forest",
      autoTheme: true,
    }),
    starlight({
      title: "pakostii",
      titleDelimiter: "|",
      favicon: "/favicon.svg",
      logo: {
        src: "./src/assets/pkst-logo.svg",
      },
      social: [
        {
          icon: "github",
          label: "GitHub",
          href: "https://github.com/sotnii/pakostii",
        },
      ],
      plugins: [starlightThemeFlexoki({ accentColor: "blue" })],
      sidebar: [
        {
          label: "Start here",
          items: ["about", "getting-started", "examples"],
        },
      ],
    }),
  ],
});
