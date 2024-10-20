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

Then, interact with the application using the API described on [openapi.yaml](./openapi.yaml).

## Stop daemon

```bash
docker-compose stop app
```

## Disk usage and attachments

`tg-notify-deleted-messages` stores message history for the time specified
in the `MESSAGES_TTL_DAYS` environment variable, with default TTL: 14 days.

You can change this interval by changing the `.env` file or by defining environment
variables at the system level.

**Be careful, your messages can fill your disk space!**

## Roadmap

### Edits

Currently the application stores only the first version of the message.
This means that after your companion edits the message and then deletes it,
you will receive the information only about the first version of the message.

The best implementation would be to store all versions of the message and receive
all of them.

#### Message versions

As soon as your companion knows that you using this tool, they will start
editing the messages, instead of deleting them. To handle this, we can store the
versions of every message, and after forwarding the original message to the bot,
it should send you the history of edits.

Or it could simply notify right away with the old version of the message every time an edit event arrives for that message.

### On-Demand Decryption

After the encryption feature was introduced, debugging queries from the logs has become harder. An on-demand decryption Flask API endpoint could help us here, but is currently complex to implement because of the way encryption is coupled with the persistence code.

## Contribution

Feel free to create issues, bug reports and pull requests. I will be very
grateful if someone implements any of the features described in the roadmap!
