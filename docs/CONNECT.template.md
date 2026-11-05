<!--
Operator template. Replace every placeholder, then delete this comment:
{{operator}} your company name, {{product}} the connector name users see,
{{url}} the connector's mail URL, {{support_url}} your support page,
{{support_email}} your support address, {{manage_url}} the connector's manage page (the connector's mail URL followed by /manage).
-->
# Connect your {{operator}} mailbox to your AI app

## What this does

{{product}} lets your AI app work with the email we host for you. It can find, read and summarise messages, open attachments, flag or file mail, save drafts and send replies. It works with Grok, Claude, ChatGPT and Codex.

## What you need

- The address and password of your mailbox with {{operator}}.
- An account with one of the AI apps below. Each section says which plans can add a connector.

Connector name: **{{product}}**
Web address: **{{url}}**

## Grok

Custom connectors are available to Grok users. If the option is missing, check your plan.

1. Go to **grok.com/connectors**. This works in a web browser and in the Grok app for iOS and Android.
2. Choose **New Connector**, then **Custom**.
3. Enter the address `{{url}}`. If asked for a name, use **{{product}}**.
4. Our sign-in page opens. Enter your mailbox address and password and click **Connect**.

**Grok Business or Enterprise:** an admin adds the connector once. In **console.x.ai**, the admin opens **Grok Business > Connectors**, clicks **+ Add Connector**, chooses **Other** and enters `{{url}}`. Each person then connects at grok.com/connectors and signs in with their own mailbox.

## Claude

Claude allows custom connectors on every plan. The Free plan allows only one.

**Free, Pro or Max:**

1. On claude.ai or in the Claude desktop app, open **Customize > Connectors**.
2. Click **+ Add**, then **Add custom connector**.
3. Enter the name **{{product}}** and the address `{{url}}`.
4. Keep the suggested sign-in settings, **Sign in now** and **Use Claude's published identity**, and click **Add**.
5. Our page called "Connect your mailbox" opens. Enter your mailbox address and password and click **Connect**.

**Team or Enterprise:** an Owner adds it once under **Organization settings > Connectors > Add > Custom > Web**. Each person then finds **{{product}}** in **Customize > Connectors**, clicks **Connect** and signs in with their own mailbox.

**In a chat:** click **+**, choose **Connectors** and check that **{{product}}** is on. Once connected, it also works in the Claude mobile app.

**Claude Code:** run this in a terminal:

```
claude mcp add --transport http mail {{url}}
```

Then type `/mcp` in Claude Code, choose **mail** and sign in on the page that opens.

## ChatGPT

ChatGPT Business, Enterprise and Edu can add custom connectors. On other plans, check whether yours offers it. You set it up on the ChatGPT website.

1. Go to **chatgpt.com/plugins**.
2. Click **+**, then **Add custom MCP server**.
3. Enter the address `{{url}}`. If asked for a name, use **{{product}}**.
4. Our sign-in page opens. Enter your mailbox address and password and click **Connect**.
5. ChatGPT shows a warning about custom servers. Accept it, then click **Create as a plugin** and install the plugin.

If ChatGPT does not let you add a custom MCP server in a workspace, ask your workspace admin. The admin can allow it under **Workspace settings > Permissions & roles**, with the permission **Create plugins with MCPs**.

**In a chat:** type **@{{product}}** to use it. ChatGPT uses it only for that message, so mention it again when a follow-up needs it to look something up or act.

## Codex

Run these two commands in a terminal:

```
codex mcp add mail --url {{url}}
codex mcp login mail
```

The second command opens our sign-in page in your browser. Enter your mailbox address and password and click **Connect**. The Codex app and the IDE extension share the same settings, so they can use it too.

## Using it

For example:

- "Summarise what came in from Acme this week."
- "Find the March invoice from Smith & Co and read me the PDF."
- "Draft a reply to Jane saying we'll deliver on Friday."
- "Reply to Jane that we'll deliver on Friday and send it." Most AI apps show you the message and ask you to approve it before it goes.
- "Forward the Smith & Co invoice to accounts@yourcompany.co.za."
- "Draft a reply to Jane and attach the quote you just wrote." The AI app can attach files it made or that you gave it.

Good to know: mail can only be moved to folders that already exist. Attachments over 5 MB can't be opened. Scanned PDFs, Office files and pictures may not be readable. Files attached together in one message can add up to about 20 MB; a message larger than your mail server accepts is stopped before it is sent, and the AI app is told the limit.

## Connecting several mailboxes

One connection can cover every mailbox you have the password for, such as all your staff's mailboxes. On the sign-in page, paste the whole list into the **Several mailboxes** box, one mailbox per line: the address, a space, then that mailbox's password. You can leave the email address and password fields above it empty; the first line is then your main mailbox. You can also copy an address column and a password column from a spreadsheet and paste them in. Blank lines are ignored, and so is a mailbox listed twice with the same password.

```
sales@yourcompany.co.za Sales-password
accounts@yourcompany.co.za Accounts-password
```

Put every mailbox you want in that first sign-in. Signing in again from your AI app makes a new connection with only the list you paste then. To change the list later, use the manage page instead (see below). Every password is checked before anything is connected, which can take a minute for many mailboxes. When it works, the page says how many mailboxes are connected, for example "87 mailboxes connected", then returns you to your AI app. If that number is lower than you expected, start the connection again in your AI app and paste the full list. If a line has a problem, nothing is connected and the page names the line, for example "Line 12 (accounts@yourcompany.co.za): address or password incorrect." The list is cleared because it holds passwords, so fix that line and paste the whole list again.

Only connect mailboxes you are entitled to read, and tell your staff in writing that their mail can be read through your AI app.

When you ask for something, name the mailbox, for example "in accounts@, find ...", or ask about all of them, for example "search all our mailboxes for the Acme quote". Mail you send goes out from the mailbox you are working in.

## Adding or removing mailboxes later

You don't need to reconnect your AI app. Go to **{{manage_url}}** and sign in with your main mailbox: the first mailbox you connected. The page lists every mailbox in your connection and shows any whose password was rejected.

- **Add mailboxes:** paste them into the box under the list, one per line (the address, a space, then the password), and click **Check and save**.
- **Staff password changed:** paste that mailbox's line with the new password into the same box and click **Check and save**.
- **Remove a mailbox:** click **Remove** next to it. The main mailbox cannot be removed.
- **Stop using the connector:** click **Disconnect**, then remove the connector in your AI app.

Changes apply straight away. Your AI app uses the new list on its next request.

If a staff member changes their password, the other mailboxes keep working and the AI tells you which one could not be opened. Enter the new password on the manage page.

## Safety and privacy

- **The AI sees what it reads.** Anything it opens goes to the company behind your AI app, under its privacy terms.
- **Sending.** {{product}} marks sending as an action that needs your approval and tells the AI to confirm with you first. Most AI apps ask before sending. They stop asking if you set the app to "always allow" or "allow all". Read every message before approving it. If your app sends without asking, tell it to show you each message first. If your app refuses to send, ask for a draft instead.
- **Moving mail** is marked as an action that can remove mail from a folder (it can move mail to Trash), so many AI apps ask before moving. **Drafting and flagging** don't need your approval, so they may happen without asking.
- **Mail is sent from the mailbox you're working in.** A copy is normally saved in its Sent folder. If the copy can't be saved, the message still goes and {{product}} tells the AI.
- **{{product}} never deletes mail permanently.** "Delete" moves mail to Trash, where you can restore it until Trash is emptied.
- **Your password is stored encrypted** and can only be unlocked by your own connection. The AI never sees it.

**To disconnect or remove it:**

- **Grok:** go to grok.com/connectors and remove **{{product}}**.
- **Claude:** in **Customize > Connectors**, open **{{product}}** and click **Disconnect** to sign out. To delete it, choose **Remove** from the three-dot menu. On Team or Enterprise, only an Owner can remove it, from **Organization settings > Connectors**.
- **Claude Code:** run `claude mcp remove mail`.
- **ChatGPT:** in **Settings > Plugins**, open **{{product}}** and choose **Disconnect**.
- **Codex:** run `codex mcp logout mail`, or `codex mcp remove mail` to delete it.
- **Everything at once:** change your mailbox password and update your mail apps. Each connection stops the next time it's used. We can also cut off your connections on request.

## Troubleshooting

- **"Address or password incorrect."** Use your full email address and mail password. After 5 wrong attempts, sign-in pauses for a while (15 minutes unless your provider set another time); the page says how long. The pause can affect everyone on your office connection.
- **"Line 12 (name@example.com): this mailbox is already listed with another password."** The same mailbox is in the list twice with different passwords. Remove the wrong line and paste the whole list again.
- **"Line 12 (name@example.com): address or password incorrect."** The password on that line of your list is wrong. Nothing was connected. Fix that line and paste the whole list again.
- **"Too many failed sign-ins for name@example.com (line 12)."** That mailbox has had too many wrong passwords recently. Wait the time the page names, or leave that line out and add the mailbox later.
- **"Mail for example.com is not hosted by {{operator}}."** That address is not on a mail server we run. Check the address for typing mistakes. If it is correct, contact us.
- **Asked to reconnect, or a Reconnect button appears.** A password has probably changed, or the connection hasn't been used for a while. Click **Reconnect**. If there is no Reconnect button, disconnect and connect again.
- **"The mail server could not be reached."** Try again shortly, and tell us if it continues.
- **Claude can't finish connecting.** Remove {{product}} and add it again, choosing **Register automatically** for the OAuth client. On Team or Enterprise, ask your Owner to do this in **Organization settings > Connectors**. Everyone then connects again.

## Getting help

Email {{support_email}} or open a ticket at {{support_url}}. Tell us which AI app you use and any message you saw. Never send us your password.
