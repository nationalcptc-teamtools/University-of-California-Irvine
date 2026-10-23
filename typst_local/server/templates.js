export const templates = {
  blank: {
    label: 'Blank',
    files: { 'main.typ': '' },
  },
  article: {
    label: 'Article',
    files: {
      'main.typ': `#import "template.typ": article

#show: article.with(
  title: [A Collaborative Document],
  authors: ("Alice", "Bob"),
)

= Introduction
Welcome to your locally hosted Typst editor! Everyone with the link can
edit this document together in real time. The preview on the right updates
as you type.

== Math
The area of a circle is $A = pi r^2$, and Euler's identity reads

$ e^(i pi) + 1 = 0. $

== Lists
- Write *bold* and _emphasized_ text.
- Use \`raw text\` for code.
+ Numbered items
+ work too.

== Tables
#table(
  columns: 3,
  [*Name*], [*Role*], [*Status*],
  [Alice], [Author], [Writing],
  [Bob], [Reviewer], [Reading],
)

#lorem(60)
`,
      'template.typ': `#let article(title: none, authors: (), body) = {
  set document(title: title, author: authors)
  set page(paper: "a4", margin: 2.5cm, numbering: "1")
  set text(size: 11pt)
  set par(justify: true)
  set heading(numbering: "1.1")

  align(center)[
    #text(size: 20pt, weight: "bold", title)
    #v(0.5em)
    #authors.join(", ")
  ]
  v(1em)
  body
}
`,
    },
  },
  slides: {
    label: 'Slides',
    files: {
      'main.typ': `#set page(paper: "presentation-16-9", margin: 2cm, fill: rgb("#1e1e2e"))
#set text(size: 24pt, fill: white)

#let slide(title, body) = {
  heading(title)
  body
  pagebreak(weak: true)
}

#align(center + horizon)[
  #text(size: 44pt, weight: "bold")[My Presentation]

  Made together in Typst
]
#pagebreak()

#slide[First point][
  - Real-time collaboration
  - Live preview
  - PDF export
]

#slide[Math][
  $ integral_0^1 x^2 dif x = 1/3 $
]
`,
    },
  },
};
