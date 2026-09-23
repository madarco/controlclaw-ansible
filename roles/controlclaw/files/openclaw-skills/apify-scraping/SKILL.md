---
name: apify-scraping
description: Read a web page, search the web and read the results, or crawl a whole site, by running Apify actors through the organisation's Apify connection. Use when a plain fetch is blocked, returns an empty JavaScript shell, or the job is more than one page.
---

# Scrape the web with Apify

The organisation's Apify token is held on its firewall, not on this box. There is no token here to
read, and none to ask for: every call goes out through the `controlclaw` MCP server, which swaps
the token in on the firewall. Use `execute_action` with an `apify.*` action id.

## When this is the right tool

- A page you tried to fetch gave you a cookie wall, a 403, or an HTML shell with no content —
  run `apify/rag-web-browser` with the URL as the query.
- "Search the web for X and read the results" — the same actor, with the search phrase as the
  query. It runs the Google search and scrapes the top results in one run.
- "Read this whole documentation site / everything under this path" — `apify/website-content-crawler`.
- A page you can already fetch, or one you can open in your own browser, does not need Apify.
  Every actor run spends the customer's Apify platform credits.

## Check the connection before the first run

```
list_connections  {"service": "apify"}
```

No row means the organisation has not connected Apify, or has not given it to this agent: say so
and stop, rather than looking for a token.

Keep the `connectionName` from that row and **pass it on every `execute_action` below**. This is
not optional: without it the runtime picks a default connection, that default is not the one this
agent was granted, and the call comes back
`connection_not_allowed: The selected connection is not granted to this runtime token.` More than
one row means more than one Apify account is connected, so say which one you used.

## Search and read: apify/rag-web-browser

```
execute_action  {"actionId": "apify.run_actor",
                 "connectionName": "<from list_connections>",
                 "input": {"actorId": "apify/rag-web-browser",
                           "input": {"query": "https://example.com/pricing",
                                     "maxResults": 3,
                                     "outputFormats": ["markdown"],
                                     "scrapingTool": "browser-playwright"},
                           "timeoutSecs": 180}}
```

- `query` is either a search phrase or one URL. A URL is fetched directly; a phrase is searched
  on Google first and the top `maxResults` pages are scraped.
- `maxResults` defaults to 3. Raise it only when the answer plainly needs more sources.
- `scrapingTool` defaults to `raw-http`, which is fast and returns nothing useful on a page that
  builds itself in JavaScript. Set `browser-playwright` when the first run comes back thin.

## Crawl a site: apify/website-content-crawler

```
execute_action  {"actionId": "apify.run_actor",
                 "connectionName": "<from list_connections>",
                 "input": {"actorId": "apify/website-content-crawler",
                           "input": {"startUrls": [{"url": "https://example.com/docs"}],
                                     "maxCrawlPages": 25,
                                     "maxResults": 25,
                                     "maxCrawlDepth": 3,
                                     "saveMarkdown": true},
                           "timeoutSecs": 900}}
```

**Always set `maxCrawlPages` and `maxResults`.** Both default to 9,999,999, so an unbounded crawl
is one forgotten field away, and the customer pays for it. Start at 25 and raise it if the pages
you got back are not enough.

The crawler asks for 8 GB by default, which is most of a small Apify plan and blocks anything
else running at the same time. `cheerio` is happy in 2 GB: pass `"memoryMbytes": 2048` next to
`timeoutSecs` when you use it.

`crawlerType` defaults to `playwright:firefox`. `cheerio` is much cheaper and works on a static
site; `playwright:adaptive` decides per page. The other values (`jsdom`, `playwright:chrome`) are
deprecated upstream — do not use them.

Narrow the crawl with `includeUrlGlobs` and `excludeUrlGlobs` rather than with a bigger page
budget.

## Wait for the run

`run_actor` returns as soon as the run is queued; `run.status` is `READY` or `RUNNING`. Poll:

```
execute_action  {"actionId": "apify.get_run",
                 "connectionName": "<from list_connections>",
                 "input": {"runId": "<run.id>", "waitForFinishSeconds": 60}}
```

`waitForFinishSeconds` is a long poll, capped at 60, so the call blocks until the run ends or the
60 seconds are up. Call it again while the status is `READY` or `RUNNING`; never poll in a tight
loop without it. Terminal statuses are `SUCCEEDED`, `FAILED`, `ABORTED` and `TIMED-OUT`. Give a
crawl a few minutes before deciding something is wrong.

## Read the results

```
execute_action  {"actionId": "apify.get_dataset_items",
                 "connectionName": "<from list_connections>",
                 "input": {"datasetId": "<run.defaultDatasetId>", "limit": 5, "clean": true}}
```

`defaultDatasetId` comes back on the run object from either call above.

- `rag-web-browser` items carry `crawl`, `metadata`, `query` and `markdown`, plus `searchResult`
  (title, description, rank) when the query was a search rather than a URL. The page content is in
  `markdown`.
- `website-content-crawler` items carry `url`, `text`, `markdown` and `metadata`.

Ask for a small `limit` first and page with `offset`. A crawl of 25 pages is a lot of text, and
all of it lands in the conversation.

## Rules

- Cite the URL of anything you report, and take it from `metadata.url` (`url` on a crawler item).
  Not from `searchResult.url`: on a search that field is a `google.com/goto?url=…` redirect, which
  is useless to the person reading your answer.
- One actor run per question. If a run comes back thin, change one input (`scrapingTool`, the
  crawler type, the page budget) and run it again — do not fire several actors at once.
- A `FAILED` run gets one retry. After that, report what Apify said instead of trying variations.
- Never widen the crawl beyond what was asked for, and never crawl a site the person did not name.
- These calls leave from the organisation's firewall, and each one appears on its Activity page
  with the action and how long it took. Inputs and results are not recorded there, so say what
  you ran when you report back.

## When it does not work

- *"This agent has no app connections yet"* — the firewall has not given this box any connection.
  The owner grants it on the agent's Integrations page in the console.
- *insufficient permissions* on `run_actor` — the customer's Apify token is scoped without
  permission to run that actor.
- The run succeeds but the dataset is refused or empty — a scoped token without access to the
  default storage of the runs it starts. Both are fixed on the token in the Apify console, not
  here.
