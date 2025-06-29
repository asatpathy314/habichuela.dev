import { Resvg } from "@resvg/resvg-js";
import { type CollectionEntry } from "astro:content";
import postOgImage from "./og-templates/post";
import siteOgImage from "./og-templates/site";

function svgBufferToPngBuffer(svg: string) {
  const resvg = new Resvg(svg);
  const pngData = resvg.render();
  return pngData.asPng();
}

export async function generateOgImageForPost(post: CollectionEntry<"blog">) {
  try {
    const svg = await postOgImage(post);
    return svgBufferToPngBuffer(svg);
  } catch {
    return new ArrayBuffer(0);
  }
}

export async function generateOgImageForSite() {
  try {
    const svg = await siteOgImage();
    return svgBufferToPngBuffer(svg);
  } catch {
    return new ArrayBuffer(0);
  }
}
