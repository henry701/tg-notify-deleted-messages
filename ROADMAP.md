# Roadmap

## Edits

Currently the application stores only the first version of the message.
This means that after your companion edits the message and then deletes it,
you will receive the information only about the first version of the message.

The best implementation would be to store all versions of the message and receive
all of them.

### Message versions

As soon as your companion knows that you using this tool, they will start
editing the messages, instead of deleting them. To handle this, we can store the
versions of every message, and after forwarding the original message to the bot,
it should send you the history of edits.

Or it could simply notify right away with the old version of the message every
time an edit event arrives for that message.

## On-Demand Decryption

After the encryption feature was introduced, debugging queries from the logs has
become harder. An on-demand decryption Flask API endpoint could help us here,
but is currently complex to implement because of the way encryption is coupled
with the persistence code.
