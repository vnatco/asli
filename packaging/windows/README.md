# Windows: the SmartScreen warning

The Windows build is **unsigned**. On first run, Microsoft Defender SmartScreen shows
"Windows protected your PC" and hides the run button behind **More info**, then
**Run anyway**.

That warning is accurate. It means the publisher is unverified, not that the file has been found to
be malicious. Verify the download yourself before trusting it:

```powershell
Get-FileHash .\asli.exe -Algorithm SHA256
```

Compare the result against the `SHA256SUMS` file attached to the release.

## Why it is unsigned

A code signing certificate costs money and, since 2023, requires the private key to live on
hardware, which complicates signing in CI. Two things are worth knowing before paying for one:

- An EV certificate no longer buys an instant SmartScreen bypass. That changed in 2024, so the
  historical reason to pay several hundred dollars a year is gone.
- Reputation is what actually clears the warning, and reputation accrues to the certificate over
  downloads and time. A brand new certificate still shows the warning at first.

## The plan

Apply to the **SignPath Foundation**, which provides free code signing for qualifying open source
projects and is recommended in Microsoft's own documentation. It requires an OSI approved license
with no commercial dual licensing and an actively maintained project, both of which hold here.

Until that is in place, the portable zip is the supported Windows artifact. There is no installer:
shipping a broken or half tested installer is worse than shipping a binary that runs from wherever
it is unpacked.
