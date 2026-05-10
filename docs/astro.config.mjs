// @ts-check
import { defineConfig } from "astro/config";
import starlight from "@astrojs/starlight";
import starlightThemeRapide from "starlight-theme-rapide";
import mermaid from "astro-mermaid";

// https://astro.build/config
export default defineConfig({
  integrations: [
    mermaid({
      theme: "forest",
      autoTheme: true,
    }),
    starlight({
      title: "Pakostii",
      social: [
        {
          icon: "github",
          label: "GitHub",
          href: "https://github.com/sotnii/pakostii",
        },
      ],
      plugins: [starlightThemeRapide()],
      sidebar: [
        {
          label: "Start here",
          items: ["about", "getting-started", "examples"],
        },
      ],
    }),
  ],
});
