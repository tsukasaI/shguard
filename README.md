# shguard

shguard is being rebuilt from zero as a `PreToolUse` hook whose verdicts rest
on a formally verified kernel. A command is allowed only when shguard's parser
read all of it and every simple command in it is covered by a closed command
catalog; anything else asks.

The previous implementation is preserved at the tag `legacy-v0.9.5`.

`acceptance/` holds command corpora carried over from it. Each row's
`command` is the input; the other fields record what the old engine decided
and are not expectations for the new one.

License: MIT OR Apache-2.0.
