// Typst language support for CodeMirror built from codemirror-lang-typst's
// native Lezer parser. Unlike its bundled `typst_lezer()`, this leaves out the
// client-side linter (the server's real compiler diagnostics are used instead)
// and ships highlight styles for both light and dark themes.
import { Language, LanguageSupport, languageDataProp, HighlightStyle, syntaxHighlighting } from '@codemirror/language';
import { tags } from '@lezer/highlight';
import {
  TypstLezerParser,
  TypstHighlightSytle,
  typstLezerLanguageData,
  typstLezerHighlighting,
  typstLezerIndentation,
  typstLezerFolding,
  typstLezerIndentService,
  typstLezerListKeymap,
  typstLezerFoldService,
  typstTags,
} from 'codemirror-lang-typst/lezer';

const parser = new TypstLezerParser(
  languageDataProp.add((type) => (type.isTop ? typstLezerLanguageData : undefined)),
  typstLezerHighlighting,
  typstLezerIndentation,
  typstLezerFolding,
);

const typstLanguage = new Language(typstLezerLanguageData, parser, [], 'typst');

const markupStyle = HighlightStyle.define([
  { tag: tags.heading, fontWeight: '700' },
  { tag: tags.strong, fontWeight: '700' },
  { tag: tags.emphasis, fontStyle: 'italic' },
  { tag: tags.link, textDecoration: 'underline' },
  { tag: tags.invalid, color: '#e5484d' },
]);

const darkStyle = HighlightStyle.define(
  [
    { tag: tags.comment, color: '#8b8b94' },
    { tag: tags.monospace, color: '#a9a9b3' },
    { tag: typstTags.mathDelimiter, color: '#7fd07a' },
    { tag: typstTags.listMarker, color: '#c79bf2' },
    { tag: tags.escape, color: '#5fc4cf' },
    { tag: tags.labelName, color: '#5fc4cf' },
    { tag: tags.keyword, color: '#ff7b86' },
    { tag: tags.null, color: '#ff7b86' },
    { tag: tags.atom, color: '#ff7b86' },
    { tag: tags.bool, color: '#ff7b86' },
    { tag: tags.number, color: '#ff8fc0' },
    { tag: tags.string, color: '#7fd07a' },
    { tag: tags.function(tags.variableName), color: '#8fa8ff' },
    { tag: typstTags.interpolated, color: '#c79bf2' },
    { tag: tags.propertyName, color: '#c79bf2' },
  ],
  { themeType: 'dark' },
);

export function typst({ dark = false } = {}) {
  return new LanguageSupport(typstLanguage, [
    syntaxHighlighting(dark ? darkStyle : TypstHighlightSytle),
    syntaxHighlighting(markupStyle),
    typstLezerIndentService,
    typstLezerListKeymap,
    typstLezerFoldService,
  ]);
}
