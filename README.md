# shguard

shguard is a `PreToolUse` hook for Claude Code. It reads the Bash command the
agent wants to run and answers Allow, Ask or Block.

## The promise

Allow means the whole command was read by shguard's parser and every simple
command in it is covered by a closed, sourced command catalog, with no
blocklist rule hit and no position that runs code. That holds under three
stated assumptions: bash reads accepted input the same way our parser does,
each catalog entry matches the real tool's argument parsing, and the
environment (PATH, shell functions, repository hooks) is not hostile. Anything
shguard cannot fully read or does not know is Ask. Allow is not a claim that a
command is "safe".

The decision logic is a small kernel written in Rust and proved with
[Creusot](https://github.com/creusot-rs/creusot).

## Status

Rebuild in progress. The previous implementation is preserved at the tag
`legacy-v0.9.5`. `acceptance/` holds command corpora carried over from it; each
row's decision fields describe the old engine, not expectations for the new
one. Usage documentation will arrive with the first release.

## License

MIT OR Apache-2.0.
