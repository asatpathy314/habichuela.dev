export const SITE = {
  website: "https://habichuela.pages.dev/", // replace this with your deployed domain
  author: "Abhishek Satpathy",
  profile: "https://github.com/asatpathy314",
  desc: "CTF writeups.",
  title: "habichuela.dev",
  ogImage: "astropaper-og.jpg",
  lightAndDarkMode: true,
  postPerIndex: 4,
  postPerPage: 4,
  scheduledPostMargin: 15 * 60 * 1000, // 15 minutes
  showArchives: true,
  showBackButton: true, // show back button in post detail
  editPost: {
    enabled: true,
    text: "Suggest Changes",
    url: "https://github.com/asatpathy314/ctf-writeups-ion/tree/main/",
  },
  dynamicOgImage: true,
} as const;
