# About

`tg-notify-deleted-messages` allows you to track messages which were deleted by
your interlocutors.

## Configuration

1. Go to <https://my.telegram.org> . Select "API development tools" and create application.
2. Copy `.env.example` file with name `.env` and change values.

## Start daemon

```bash
docker-compose up -d app
```

**P.S: You will need to send your telegram sign-in code to the URL logged by the application on the first time.**

## Stop daemon

```bash
docker-compose stop app
```

## Disk usage and attachments

`tg-notify-deleted-messages` stores message history for the time specified
in the `MESSAGES_TTL_DAYS` environment variable, with default TTL: 14 days.

You can change this interval by changing the `.env` file or by defining environment
variables at the system level.

**Be careful, your messages can fill your disk space.**

## Roadmap

### Display the chat from which the message was deleted

Now it sends only the information about the sender of the message, but it
doesn't point from which entity the message was deleted.

### Preload the history when the application starts

If you want to support old messages, but you start this application after those messages were sent,
in case those messages are deleted the application will be unable to notify you about them.

Preloading old messages (limited by `MESSAGES_TTL_DAYS`) would fix this issue.

### Edits

Currently the application stores only the first version of the message.
This means that after your companion edits the message and then deletes it,
you will receive the information only about the first version of the message.

The best implementation would be to store all versions of the message and receive
all of them.

#### Messages versions

As soon as your companion knows that you using this tool, they will start
editing the messages, instead of deleting them. To handle this, we can store the
versions of every message, and after forwarding the original message to the bot,
it should send you the history of edits.

## Contribution

Feel free to create issues, bug reports and pull requests. I will be very
grateful, if someone implements one of the features described in the roadmap!
