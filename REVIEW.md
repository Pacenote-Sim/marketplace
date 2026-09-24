# Reviewing a plugin

The checks have passed, or the pull request would not be in front of you. Your job is the part a
program cannot do: read the code and decide whether Pacenote's name may go on it.

Read the whole tag for a first listing; read the diff since the last approved tag for an update.
Then write a paragraph in the pull request answering the questions below, set `approved` and
`reviewer` on the version, and merge. If the answer to any question is no, say which and close.

## The questions

1. **Does it do what the summary says, and nothing the summary does not say?** A companion that
   "plays the engineer's lines" and also posts the driver's name somewhere is a no.
2. **Does everything it sends leave through a declared door?** For a client plugin, only through
   `Host.Do` to its own plugin's routes, and only the data the events gave it. For a server plugin,
   only to the hosts in `calls`. The hosts check found the literals; you find the intent.
3. **Does it touch nothing it was not lent?** No credential of its own, no file the contract did not
   give it, no other plugin's data. A server plugin that reads a table it did not create is a no.
4. **Does it keep nothing about the driver it does not need?** Telemetry about the plugin's own use,
   analytics, crash reporting to a third party: all no, unless declared in `calls` and explained in
   the summary.
5. **Are the reasons in the manifest true?** Every `dependencies`, `imports_allow` and `not_hosts`
   entry has a reason. Check that the code matches the reason. `os/exec` "to speak through the
   machine's voice" is fine if that is all it runs.
6. **Would a driver be surprised by anything it does?** Audio at the wrong time, a page that leaves
   the window, a setting it changes without being asked.
7. **Is the author reachable?** The contact address works. For a private repository,
   `pacenote-review` has access and the tag you checked is the tag in the manifest.

## What you write

Three to eight sentences: what the plugin does, what you looked at hardest, anything an operator
should know before enabling it. It is posted on the pull request and stays there as the record of
the approval.

## What you do not do

You do not fix the plugin. If it needs a change, say what and let the author tag again. You do not
approve a version you did not read. You do not approve your own plugin; a second reviewer does.
