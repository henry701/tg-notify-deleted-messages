# Roadmap

## On-Demand Decryption

After the encryption feature was introduced, debugging queries from the logs has
become harder. An on-demand decryption Flask API endpoint could help us here,
but is currently complex to implement because of the way encryption is coupled
with the persistence code.

