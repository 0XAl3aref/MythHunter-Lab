<html><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8"/><title>Zeus Banking Trojan Simulation</title><style>
/* cspell:disable-file */
/* webkit printing magic: print all background colors */
html {
	-webkit-print-color-adjust: exact;
}
* {
	box-sizing: border-box;
	-webkit-print-color-adjust: exact;
}

html,
body {
	margin: 0;
	padding: 0;
}
@media only screen {
	body {
		margin: 2em auto;
		max-width: 900px;
		color: rgb(55, 53, 47);
	}
}

body {
	line-height: 1.5;
	white-space: pre-wrap;
}

a,
a.visited {
	color: inherit;
	text-decoration: underline;
}

.pdf-relative-link-path {
	font-size: 80%;
	color: #444;
}

h1,
h2,
h3 {
	letter-spacing: -0.01em;
	line-height: 1.2;
	font-weight: 600;
	margin-bottom: 0;
}

.page-title {
	font-size: 2.5rem;
	font-weight: 700;
	margin-top: 0;
	margin-bottom: 0.75em;
}

h1 {
	font-size: 1.875rem;
	margin-top: 1.875rem;
}

h2 {
	font-size: 1.5rem;
	margin-top: 1.5rem;
}

h3 {
	font-size: 1.25rem;
	margin-top: 1.25rem;
}

.source {
	border: 1px solid #ddd;
	border-radius: 3px;
	padding: 1.5em;
	word-break: break-all;
}

.callout {
	border-radius: 3px;
	padding: 1rem;
}

figure {
	margin: 1.25em 0;
	page-break-inside: avoid;
}

figcaption {
	opacity: 0.5;
	font-size: 85%;
	margin-top: 0.5em;
}

mark {
	background-color: transparent;
}

.indented {
	padding-left: 1.5em;
}

hr {
	background: transparent;
	display: block;
	width: 100%;
	height: 1px;
	visibility: visible;
	border: none;
	border-bottom: 1px solid rgba(55, 53, 47, 0.09);
}

img {
	max-width: 100%;
}

@media only print {
	img {
		max-height: 100vh;
		object-fit: contain;
	}
}

@page {
	margin: 1in;
}

.collection-content {
	font-size: 0.875rem;
}

.column-list {
	display: flex;
	justify-content: space-between;
}

.column {
	padding: 0 1em;
}

.column:first-child {
	padding-left: 0;
}

.column:last-child {
	padding-right: 0;
}

.table_of_contents-item {
	display: block;
	font-size: 0.875rem;
	line-height: 1.3;
	padding: 0.125rem;
}

.table_of_contents-indent-1 {
	margin-left: 1.5rem;
}

.table_of_contents-indent-2 {
	margin-left: 3rem;
}

.table_of_contents-indent-3 {
	margin-left: 4.5rem;
}

.table_of_contents-link {
	text-decoration: none;
	opacity: 0.7;
	border-bottom: 1px solid rgba(55, 53, 47, 0.18);
}

table,
th,
td {
	border: 1px solid rgba(55, 53, 47, 0.09);
	border-collapse: collapse;
}

table {
	border-left: none;
	border-right: none;
}

th,
td {
	font-weight: normal;
	padding: 0.25em 0.5em;
	line-height: 1.5;
	min-height: 1.5em;
	text-align: left;
}

th {
	color: rgba(55, 53, 47, 0.6);
}

ol,
ul {
	margin: 0;
	margin-block-start: 0.6em;
	margin-block-end: 0.6em;
}

li > ol:first-child,
li > ul:first-child {
	margin-block-start: 0.6em;
}

ul > li {
	list-style: disc;
}

ul.to-do-list {
	padding-inline-start: 0;
}

ul.to-do-list > li {
	list-style: none;
}

.to-do-children-checked {
	text-decoration: line-through;
	opacity: 0.375;
}

ul.toggle > li {
	list-style: none;
}

ul {
	padding-inline-start: 1.7em;
}

ul > li {
	padding-left: 0.1em;
}

ol {
	padding-inline-start: 1.6em;
}

ol > li {
	padding-left: 0.2em;
}

.mono ol {
	padding-inline-start: 2em;
}

.mono ol > li {
	text-indent: -0.4em;
}

.toggle {
	padding-inline-start: 0em;
	list-style-type: none;
}

/* Indent toggle children */
.toggle > li > details {
	padding-left: 1.7em;
}

.toggle > li > details > summary {
	margin-left: -1.1em;
}

.selected-value {
	display: inline-block;
	padding: 0 0.5em;
	background: rgba(206, 205, 202, 0.5);
	border-radius: 3px;
	margin-right: 0.5em;
	margin-top: 0.3em;
	margin-bottom: 0.3em;
	white-space: nowrap;
}

.collection-title {
	display: inline-block;
	margin-right: 1em;
}

.page-description {
	margin-bottom: 2em;
}

.simple-table {
	margin-top: 1em;
	font-size: 0.875rem;
	empty-cells: show;
}
.simple-table td {
	height: 29px;
	min-width: 120px;
}

.simple-table th {
	height: 29px;
	min-width: 120px;
}

.simple-table-header-color {
	background: rgb(247, 246, 243);
	color: black;
}
.simple-table-header {
	font-weight: 500;
}

time {
	opacity: 0.5;
}

.icon {
	display: inline-block;
	max-width: 1.2em;
	max-height: 1.2em;
	text-decoration: none;
	vertical-align: text-bottom;
	margin-right: 0.5em;
}

img.icon {
	border-radius: 3px;
}

.user-icon {
	width: 1.5em;
	height: 1.5em;
	border-radius: 100%;
	margin-right: 0.5rem;
}

.user-icon-inner {
	font-size: 0.8em;
}

.text-icon {
	border: 1px solid #000;
	text-align: center;
}

.page-cover-image {
	display: block;
	object-fit: cover;
	width: 100%;
	max-height: 30vh;
}

.page-header-icon {
	font-size: 3rem;
	margin-bottom: 1rem;
}

.page-header-icon-with-cover {
	margin-top: -0.72em;
	margin-left: 0.07em;
}

.page-header-icon img {
	border-radius: 3px;
}

.link-to-page {
	margin: 1em 0;
	padding: 0;
	border: none;
	font-weight: 500;
}

p > .user {
	opacity: 0.5;
}

td > .user,
td > time {
	white-space: nowrap;
}

input[type="checkbox"] {
	transform: scale(1.5);
	margin-right: 0.6em;
	vertical-align: middle;
}

p {
	margin-top: 0.5em;
	margin-bottom: 0.5em;
}

.image {
	border: none;
	margin: 1.5em 0;
	padding: 0;
	border-radius: 0;
	text-align: center;
}

.code,
code {
	background: rgba(135, 131, 120, 0.15);
	border-radius: 3px;
	padding: 0.2em 0.4em;
	border-radius: 3px;
	font-size: 85%;
	tab-size: 2;
}

code {
	color: #eb5757;
}

.code {
	padding: 1.5em 1em;
}

.code-wrap {
	white-space: pre-wrap;
	word-break: break-all;
}

.code > code {
	background: none;
	padding: 0;
	font-size: 100%;
	color: inherit;
}

blockquote {
	font-size: 1.25em;
	margin: 1em 0;
	padding-left: 1em;
	border-left: 3px solid rgb(55, 53, 47);
}

.bookmark {
	text-decoration: none;
	max-height: 8em;
	padding: 0;
	display: flex;
	width: 100%;
	align-items: stretch;
}

.bookmark-title {
	font-size: 0.85em;
	overflow: hidden;
	text-overflow: ellipsis;
	height: 1.75em;
	white-space: nowrap;
}

.bookmark-text {
	display: flex;
	flex-direction: column;
}

.bookmark-info {
	flex: 4 1 180px;
	padding: 12px 14px 14px;
	display: flex;
	flex-direction: column;
	justify-content: space-between;
}

.bookmark-image {
	width: 33%;
	flex: 1 1 180px;
	display: block;
	position: relative;
	object-fit: cover;
	border-radius: 1px;
}

.bookmark-description {
	color: rgba(55, 53, 47, 0.6);
	font-size: 0.75em;
	overflow: hidden;
	max-height: 4.5em;
	word-break: break-word;
}

.bookmark-href {
	font-size: 0.75em;
	margin-top: 0.25em;
}

.sans { font-family: ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI Variable Display", "Segoe UI", Helvetica, "Apple Color Emoji", Arial, sans-serif, "Segoe UI Emoji", "Segoe UI Symbol"; }
.code { font-family: "SFMono-Regular", Menlo, Consolas, "PT Mono", "Liberation Mono", Courier, monospace; }
.serif { font-family: Lyon-Text, Georgia, ui-serif, serif; }
.mono { font-family: iawriter-mono, Nitti, Menlo, Courier, monospace; }
.pdf .sans { font-family: Inter, ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI Variable Display", "Segoe UI", Helvetica, "Apple Color Emoji", Arial, sans-serif, "Segoe UI Emoji", "Segoe UI Symbol", 'Twemoji', 'Noto Color Emoji', 'Noto Sans CJK JP'; }
.pdf:lang(zh-CN) .sans { font-family: Inter, ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI Variable Display", "Segoe UI", Helvetica, "Apple Color Emoji", Arial, sans-serif, "Segoe UI Emoji", "Segoe UI Symbol", 'Twemoji', 'Noto Color Emoji', 'Noto Sans CJK SC'; }
.pdf:lang(zh-TW) .sans { font-family: Inter, ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI Variable Display", "Segoe UI", Helvetica, "Apple Color Emoji", Arial, sans-serif, "Segoe UI Emoji", "Segoe UI Symbol", 'Twemoji', 'Noto Color Emoji', 'Noto Sans CJK TC'; }
.pdf:lang(ko-KR) .sans { font-family: Inter, ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI Variable Display", "Segoe UI", Helvetica, "Apple Color Emoji", Arial, sans-serif, "Segoe UI Emoji", "Segoe UI Symbol", 'Twemoji', 'Noto Color Emoji', 'Noto Sans CJK KR'; }
.pdf .code { font-family: Source Code Pro, "SFMono-Regular", Menlo, Consolas, "PT Mono", "Liberation Mono", Courier, monospace, 'Twemoji', 'Noto Color Emoji', 'Noto Sans Mono CJK JP'; }
.pdf:lang(zh-CN) .code { font-family: Source Code Pro, "SFMono-Regular", Menlo, Consolas, "PT Mono", "Liberation Mono", Courier, monospace, 'Twemoji', 'Noto Color Emoji', 'Noto Sans Mono CJK SC'; }
.pdf:lang(zh-TW) .code { font-family: Source Code Pro, "SFMono-Regular", Menlo, Consolas, "PT Mono", "Liberation Mono", Courier, monospace, 'Twemoji', 'Noto Color Emoji', 'Noto Sans Mono CJK TC'; }
.pdf:lang(ko-KR) .code { font-family: Source Code Pro, "SFMono-Regular", Menlo, Consolas, "PT Mono", "Liberation Mono", Courier, monospace, 'Twemoji', 'Noto Color Emoji', 'Noto Sans Mono CJK KR'; }
.pdf .serif { font-family: PT Serif, Lyon-Text, Georgia, ui-serif, serif, 'Twemoji', 'Noto Color Emoji', 'Noto Serif CJK JP'; }
.pdf:lang(zh-CN) .serif { font-family: PT Serif, Lyon-Text, Georgia, ui-serif, serif, 'Twemoji', 'Noto Color Emoji', 'Noto Serif CJK SC'; }
.pdf:lang(zh-TW) .serif { font-family: PT Serif, Lyon-Text, Georgia, ui-serif, serif, 'Twemoji', 'Noto Color Emoji', 'Noto Serif CJK TC'; }
.pdf:lang(ko-KR) .serif { font-family: PT Serif, Lyon-Text, Georgia, ui-serif, serif, 'Twemoji', 'Noto Color Emoji', 'Noto Serif CJK KR'; }
.pdf .mono { font-family: PT Mono, iawriter-mono, Nitti, Menlo, Courier, monospace, 'Twemoji', 'Noto Color Emoji', 'Noto Sans Mono CJK JP'; }
.pdf:lang(zh-CN) .mono { font-family: PT Mono, iawriter-mono, Nitti, Menlo, Courier, monospace, 'Twemoji', 'Noto Color Emoji', 'Noto Sans Mono CJK SC'; }
.pdf:lang(zh-TW) .mono { font-family: PT Mono, iawriter-mono, Nitti, Menlo, Courier, monospace, 'Twemoji', 'Noto Color Emoji', 'Noto Sans Mono CJK TC'; }
.pdf:lang(ko-KR) .mono { font-family: PT Mono, iawriter-mono, Nitti, Menlo, Courier, monospace, 'Twemoji', 'Noto Color Emoji', 'Noto Sans Mono CJK KR'; }
.highlight-default {
	color: rgba(55, 53, 47, 1);
}
.highlight-gray {
	color: rgba(120, 119, 116, 1);
	fill: rgba(120, 119, 116, 1);
}
.highlight-brown {
	color: rgba(159, 107, 83, 1);
	fill: rgba(159, 107, 83, 1);
}
.highlight-orange {
	color: rgba(217, 115, 13, 1);
	fill: rgba(217, 115, 13, 1);
}
.highlight-yellow {
	color: rgba(203, 145, 47, 1);
	fill: rgba(203, 145, 47, 1);
}
.highlight-teal {
	color: rgba(68, 131, 97, 1);
	fill: rgba(68, 131, 97, 1);
}
.highlight-blue {
	color: rgba(51, 126, 169, 1);
	fill: rgba(51, 126, 169, 1);
}
.highlight-purple {
	color: rgba(144, 101, 176, 1);
	fill: rgba(144, 101, 176, 1);
}
.highlight-pink {
	color: rgba(193, 76, 138, 1);
	fill: rgba(193, 76, 138, 1);
}
.highlight-red {
	color: rgba(212, 76, 71, 1);
	fill: rgba(212, 76, 71, 1);
}
.highlight-default_background {
	color: rgba(55, 53, 47, 1);
}
.highlight-gray_background {
	background: rgba(241, 241, 239, 1);
}
.highlight-brown_background {
	background: rgba(244, 238, 238, 1);
}
.highlight-orange_background {
	background: rgba(251, 236, 221, 1);
}
.highlight-yellow_background {
	background: rgba(251, 243, 219, 1);
}
.highlight-teal_background {
	background: rgba(237, 243, 236, 1);
}
.highlight-blue_background {
	background: rgba(231, 243, 248, 1);
}
.highlight-purple_background {
	background: rgba(244, 240, 247, 0.8);
}
.highlight-pink_background {
	background: rgba(249, 238, 243, 0.8);
}
.highlight-red_background {
	background: rgba(253, 235, 236, 1);
}
.block-color-default {
	color: inherit;
	fill: inherit;
}
.block-color-gray {
	color: rgba(120, 119, 116, 1);
	fill: rgba(120, 119, 116, 1);
}
.block-color-brown {
	color: rgba(159, 107, 83, 1);
	fill: rgba(159, 107, 83, 1);
}
.block-color-orange {
	color: rgba(217, 115, 13, 1);
	fill: rgba(217, 115, 13, 1);
}
.block-color-yellow {
	color: rgba(203, 145, 47, 1);
	fill: rgba(203, 145, 47, 1);
}
.block-color-teal {
	color: rgba(68, 131, 97, 1);
	fill: rgba(68, 131, 97, 1);
}
.block-color-blue {
	color: rgba(51, 126, 169, 1);
	fill: rgba(51, 126, 169, 1);
}
.block-color-purple {
	color: rgba(144, 101, 176, 1);
	fill: rgba(144, 101, 176, 1);
}
.block-color-pink {
	color: rgba(193, 76, 138, 1);
	fill: rgba(193, 76, 138, 1);
}
.block-color-red {
	color: rgba(212, 76, 71, 1);
	fill: rgba(212, 76, 71, 1);
}
.block-color-default_background {
	color: inherit;
	fill: inherit;
}
.block-color-gray_background {
	background: rgba(241, 241, 239, 1);
}
.block-color-brown_background {
	background: rgba(244, 238, 238, 1);
}
.block-color-orange_background {
	background: rgba(251, 236, 221, 1);
}
.block-color-yellow_background {
	background: rgba(251, 243, 219, 1);
}
.block-color-teal_background {
	background: rgba(237, 243, 236, 1);
}
.block-color-blue_background {
	background: rgba(231, 243, 248, 1);
}
.block-color-purple_background {
	background: rgba(244, 240, 247, 0.8);
}
.block-color-pink_background {
	background: rgba(249, 238, 243, 0.8);
}
.block-color-red_background {
	background: rgba(253, 235, 236, 1);
}
.select-value-color-uiBlue { background-color: rgba(35, 131, 226, .07); }
.select-value-color-pink { background-color: rgba(245, 224, 233, 1); }
.select-value-color-purple { background-color: rgba(232, 222, 238, 1); }
.select-value-color-green { background-color: rgba(219, 237, 219, 1); }
.select-value-color-gray { background-color: rgba(227, 226, 224, 1); }
.select-value-color-transparentGray { background-color: rgba(227, 226, 224, 0); }
.select-value-color-translucentGray { background-color: rgba(0, 0, 0, 0.06); }
.select-value-color-orange { background-color: rgba(250, 222, 201, 1); }
.select-value-color-brown { background-color: rgba(238, 224, 218, 1); }
.select-value-color-red { background-color: rgba(255, 226, 221, 1); }
.select-value-color-yellow { background-color: rgba(253, 236, 200, 1); }
.select-value-color-blue { background-color: rgba(211, 229, 239, 1); }
.select-value-color-pageGlass { background-color: undefined; }
.select-value-color-washGlass { background-color: undefined; }

.checkbox {
	display: inline-flex;
	vertical-align: text-bottom;
	width: 16;
	height: 16;
	background-size: 16px;
	margin-left: 2px;
	margin-right: 5px;
}

.checkbox-on {
	background-image: url("data:image/svg+xml;charset=UTF-8,%3Csvg%20width%3D%2216%22%20height%3D%2216%22%20viewBox%3D%220%200%2016%2016%22%20fill%3D%22none%22%20xmlns%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%22%3E%0A%3Crect%20width%3D%2216%22%20height%3D%2216%22%20fill%3D%22%2358A9D7%22%2F%3E%0A%3Cpath%20d%3D%22M6.71429%2012.2852L14%204.9995L12.7143%203.71436L6.71429%209.71378L3.28571%206.2831L2%207.57092L6.71429%2012.2852Z%22%20fill%3D%22white%22%2F%3E%0A%3C%2Fsvg%3E");
}

.checkbox-off {
	background-image: url("data:image/svg+xml;charset=UTF-8,%3Csvg%20width%3D%2216%22%20height%3D%2216%22%20viewBox%3D%220%200%2016%2016%22%20fill%3D%22none%22%20xmlns%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%22%3E%0A%3Crect%20x%3D%220.75%22%20y%3D%220.75%22%20width%3D%2214.5%22%20height%3D%2214.5%22%20fill%3D%22white%22%20stroke%3D%22%2336352F%22%20stroke-width%3D%221.5%22%2F%3E%0A%3C%2Fsvg%3E");
}
	
</style></head><body><article id="1152c7d3-8aff-80e4-b21a-c9f3630d507f" class="page sans"><header><img class="page-cover-image" src="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/artbreeder-image-2025-01-18T10_35_39.306Z.jpeg" style="object-position:center 50%"/><h1 class="page-title">Zeus Banking Trojan Simulation</h1><p class="page-description"></p></header><div class="page-body"><h1 id="178536e2-3f10-4de8-8e56-3b41746b5cfc" class="">Overview</h1><p id="ad65469d-84ff-4220-a016-fb2f5c3584fb" class="">Zeus (also known as Zbot) is a notorious banking trojan that targets financial credentials and personal information. This simulation will explore its behavior and detection methods.</p><hr id="1842c7d3-8aff-80e0-b445-da24f8126b54"/><h2 id="4676d582-ce84-4cf0-a5ee-6bce15873562" class="">Technical Analysis</h2><ul id="ce21532b-2238-44ee-a250-d3f4ab72ce1e" class="bulleted-list"><li style="list-style-type:disc">Initial Infection Vector</li></ul><ul id="97e6e76f-3cb5-4d31-8fce-122dd2cdad6b" class="bulleted-list"><li style="list-style-type:disc">Command &amp; Control Communication</li></ul><ul id="9c1d339e-65cc-401b-96dc-e3bbdc03661d" class="bulleted-list"><li style="list-style-type:disc">Data Exfiltration Methods</li></ul><ul id="5f3d8755-4fee-46fd-8e2b-cc6e940050c2" class="bulleted-list"><li style="list-style-type:disc">Persistence Mechanisms</li></ul><hr id="1842c7d3-8aff-8091-a34a-d1854e35c87b"/><h2 id="3244c61f-cac6-4d1a-a6a5-3ffbcd83e80f" class="">Detection Methods</h2><ul id="fdf82e9d-8598-470c-8ba7-d7854636120e" class="bulleted-list"><li style="list-style-type:disc">Network Traffic Analysis</li></ul><ul id="7fc671f8-e69e-435f-afef-cdf6ee6dd6be" class="bulleted-list"><li style="list-style-type:disc">System Behavior Monitoring</li></ul><ul id="cd0bc0e1-d66a-4703-85e0-a20b0a65e426" class="bulleted-list"><li style="list-style-type:disc">Memory Analysis</li></ul><ul id="42489f84-1e64-4df3-9009-8c34d10b7bde" class="bulleted-list"><li style="list-style-type:disc">Registry Changes</li></ul><hr id="1842c7d3-8aff-80de-9eec-f5fe3eb788c9"/><h2 id="892512db-f6a5-496b-94e5-a673a1f2c64e" class="">Simulation Components</h2><ul id="c2d63922-8e78-4dc5-8ae2-9347b22a9bd2" class="to-do-list"><li><div class="checkbox checkbox-off"></div> <span class="to-do-children-unchecked">Set up isolated testing environment</span><div class="indented"></div></li></ul><ul id="3a86a409-6adc-457b-b353-a7ea3c23b585" class="to-do-list"><li><div class="checkbox checkbox-off"></div> <span class="to-do-children-unchecked">Configure network monitoring tools</span><div class="indented"></div></li></ul><ul id="b9803a40-ffce-4713-9016-bc4e302c34d7" class="to-do-list"><li><div class="checkbox checkbox-off"></div> <span class="to-do-children-unchecked">Implement logging mechanisms</span><div class="indented"></div></li></ul><ul id="31e021de-9767-4a06-9d2d-6e5a27808dbe" class="to-do-list"><li><div class="checkbox checkbox-off"></div> <span class="to-do-children-unchecked">Prepare analysis tools</span><div class="indented"></div></li></ul><figure class="block-color-red callout" style="white-space:pre-wrap;display:flex" id="aa4defb6-fed1-49e0-9e5f-59a76ee36794"><div style="width:100%">Warning: This simulation is for educational purposes only. Never deploy malware on production systems or networks.</div></figure><hr id="0cd86f93-071c-4815-a60d-45a2e2fb2068"/><h2 id="1842c7d3-8aff-80dd-b63c-c5886d6b8ef0" class="">Expected Behaviors</h2><p id="6eeda7a8-50cb-497e-b2bd-9ac575d4fe3f" class="">The simulation will demonstrate:</p><ul id="393f6e37-fd66-4179-a84a-49a30a7c9ce3" class="bulleted-list"><li style="list-style-type:disc">Web injection techniques</li></ul><ul id="668353cc-e8b7-4c33-8f81-3155c1c99c2b" class="bulleted-list"><li style="list-style-type:disc">Form grabbing capabilities</li></ul><ul id="be3136d0-6fb7-4c42-9208-156a2bf26ed5" class="bulleted-list"><li style="list-style-type:disc">Man-in-the-browser attacks</li></ul><ul id="001ec5da-8d7a-48ad-a68b-476933cec452" class="bulleted-list"><li style="list-style-type:disc">Keystroke logging</li></ul><hr id="1842c7d3-8aff-8068-a9dd-ea29a786cf47"/><h2 id="1842c7d3-8aff-8048-bb91-dc1199f444cc" class="">Safety Measures</h2><ul id="ec6bdc81-c617-4103-957a-29bffb7ede83" class="bulleted-list"><li style="list-style-type:disc">Use isolated virtual environment</li></ul><ul id="616c1125-0eb3-4c28-a1ff-db4167828002" class="bulleted-list"><li style="list-style-type:disc">Implement network segmentation</li></ul><ul id="5168b4e0-f1a6-4bd0-b1d5-b60c0dca8676" class="bulleted-list"><li style="list-style-type:disc">Monitor all traffic carefully</li></ul><ul id="43210827-4a2f-453f-abb2-6fb01970f333" class="bulleted-list"><li style="list-style-type:disc">Document all findings securely</li></ul><hr id="1842c7d3-8aff-80fd-9432-ee433972abd8"/><figure id="1842c7d3-8aff-8021-9da3-f8131b98a988" class="image"><a href="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/300.png"><img style="width:707.984375px" src="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/300.png"/></a></figure><p id="1842c7d3-8aff-803d-8ec8-d1ae03c92fdd" class="">
</p><p id="b48ad677-b6ba-4218-b65e-4fddb19dda01" class="">Note: This diagram represents a general flow of how Zeus banking trojan typically operates in attacking banking systems and the corresponding security measures. Specific bank names are not included for security reasons.</p><hr id="1842c7d3-8aff-802b-8c0a-e5f081dcb9a3"/><details open=""><summary style="font-weight:600;font-size:1.5em;line-height:1.3;margin:0">Incident response process that will be executed for recovering system to the normal mode is!</summary><div class="indented"><p id="1842c7d3-8aff-80fc-b600-e245fe944663" class="">
</p><details open=""><summary style="font-weight:600;font-size:1.5em;line-height:1.3;margin:0"><mark class="highlight-teal_background">1.  </mark><mark class="highlight-teal_background"><strong>Preparation</strong></mark></summary><div class="indented"><p id="1842c7d3-8aff-803f-a06e-f9d156862654" class="">
</p><blockquote id="1842c7d3-8aff-80c8-b736-eff786358701" class=""><mark class="highlight-blue_background"><strong> This step involves setting up processes, tools, and resources to ensure an organization can effectively respond to incidents.</strong></mark></blockquote><details open=""><summary style="font-weight:600;font-size:1.25em;line-height:1.3;margin:0"><strong>Key Actions: </strong></summary><div class="indented"><ul id="1842c7d3-8aff-80ce-8075-fef2fec6f706" class="bulleted-list"><li style="list-style-type:disc">Develop and document an <strong>Incident Response Plan (IRP)</strong>.</li></ul><ul id="1842c7d3-8aff-80c3-a2c7-e0a47478a762" class="bulleted-list"><li style="list-style-type:disc">Establish an <strong>Incident Response Team (IRT)</strong> with defined roles and responsibilities.</li></ul><ul id="1842c7d3-8aff-8043-b54f-da7fb315959c" class="bulleted-list"><li style="list-style-type:disc">Deploy and configure security tools like SIEMs, EDRs, and firewalls.</li></ul><ul id="1842c7d3-8aff-8066-a345-d52fc407f4a0" class="bulleted-list"><li style="list-style-type:disc">Train staff with <strong>cybersecurity awareness</strong> and conduct regular incident response drills (e.g., tabletop exercises).</li></ul><ul id="1842c7d3-8aff-80fc-b9aa-d2107b5d4c2f" class="bulleted-list"><li style="list-style-type:disc">Maintain an updated <strong>inventory of critical assets</strong> and their associated risks.</li></ul><ul id="1842c7d3-8aff-8056-a2b8-db123e0686ef" class="bulleted-list"><li style="list-style-type:disc">Develop playbooks for common attack scenarios (e.g., phishing, ransomware, data breaches).</li></ul></div></details></div></details><details open=""><summary style="font-weight:600;font-size:1.5em;line-height:1.3;margin:0"><mark class="highlight-teal_background"><strong>2.  Identification</strong></mark></summary><div class="indented"><p id="1842c7d3-8aff-8013-8b3a-f69842a90538" class="">
</p><blockquote id="1842c7d3-8aff-8019-90e6-e2d63279c97e" class="">In this phase, you detect and confirm potential security incidents by analyzing alerts, logs, and behaviors.</blockquote><details open=""><summary style="font-weight:600;font-size:1.5em;line-height:1.3;margin:0"><mark class="highlight-blue_background"><strong>Key Actions:</strong></mark></summary><div class="indented"><ul id="1842c7d3-8aff-808b-a307-cd4c53cdc6c6" class="bulleted-list"><li style="list-style-type:disc"><strong>Monitor systems</strong> and networks using tools like SIEM, IDS/IPS, and endpoint security tools.</li></ul><ul id="1842c7d3-8aff-803a-b9d2-e6c83b9e9ab2" class="bulleted-list"><li style="list-style-type:disc">Analyze alerts and anomalies to confirm if an incident is occurring.</li></ul><ul id="1842c7d3-8aff-8067-89fd-c3f1bf49d64e" class="bulleted-list"><li style="list-style-type:disc">Gather forensic data, including logs, system snapshots, and network traffic.</li></ul><ul id="1842c7d3-8aff-8033-9277-ecfed8f1f979" class="bulleted-list"><li style="list-style-type:disc">Classify and prioritize the incident based on its severity, impact, and type (e.g., phishing, ransomware).</li></ul><ul id="1842c7d3-8aff-80de-8126-c4d6c1fa2ed5" class="bulleted-list"><li style="list-style-type:disc">Answer critical questions:<ul id="1842c7d3-8aff-8066-8ae8-e9361f8ef2ab" class="bulleted-list"><li style="list-style-type:circle">What happened?</li></ul><ul id="1842c7d3-8aff-8084-b7a5-c27f24e36e25" class="bulleted-list"><li style="list-style-type:circle">When did it occur?</li></ul><ul id="1842c7d3-8aff-80f1-98a2-cb17bf4273a6" class="bulleted-list"><li style="list-style-type:circle">Who/what is impacted?</li></ul><ul id="1842c7d3-8aff-802e-af4a-f554c745a03a" class="bulleted-list"><li style="list-style-type:circle">What is the potential impact?</li></ul></li></ul></div></details></div></details><details open=""><summary style="font-weight:600;font-size:1.5em;line-height:1.3;margin:0"><mark class="highlight-teal_background">3. </mark><mark class="highlight-teal_background"><strong> Containment</strong></mark></summary><div class="indented"><p id="1842c7d3-8aff-806f-8110-c85e07ccec40" class="">
</p><blockquote id="1842c7d3-8aff-8041-924a-eaebcc104831" class="">This step focuses on stopping the spread of the attack and limiting its damage.</blockquote><details open=""><summary style="font-weight:600;font-size:1.5em;line-height:1.3;margin:0"><mark class="highlight-blue_background"><strong>Key Actions:</strong></mark></summary><div class="indented"><ul id="1842c7d3-8aff-8082-a973-d38e2b11056a" class="bulleted-list"><li style="list-style-type:disc"><strong>Short-term containment</strong>: Isolate affected systems (e.g., unplug from the network, disable accounts).</li></ul><ul id="1842c7d3-8aff-8065-8063-d08b59be2ace" class="bulleted-list"><li style="list-style-type:disc"><strong>Long-term containment</strong>: Set up temporary solutions, such as deploying new firewalls or network segments.</li></ul><ul id="1842c7d3-8aff-8029-b222-eacfa8362044" class="bulleted-list"><li style="list-style-type:disc">Block malicious domains, IPs, and email addresses in firewalls or DNS settings.</li></ul><ul id="1842c7d3-8aff-805c-be86-f6395f628892" class="bulleted-list"><li style="list-style-type:disc">Implement patches or workarounds to prevent further exploitation.</li></ul><ul id="1842c7d3-8aff-808f-9306-ee0977a1d613" class="bulleted-list"><li style="list-style-type:disc">Preserve evidence for further investigation (e.g., disk images, memory dumps).</li></ul></div></details></div></details><details open=""><summary style="font-weight:600;font-size:1.5em;line-height:1.3;margin:0"><mark class="highlight-teal_background">4.  </mark><mark class="highlight-teal_background"><strong>Eradication</strong></mark></summary><div class="indented"><blockquote id="1842c7d3-8aff-80c0-88cd-fe95efbc5626" class="">In this phase, you remove the threat from your environment to prevent further compromise.</blockquote><details open=""><summary style="font-weight:600;font-size:1.5em;line-height:1.3;margin:0"><mark class="highlight-blue_background"><strong>Key Actions:</strong></mark></summary><div class="indented"><ul id="1842c7d3-8aff-8032-9e0f-edc1dd1aad00" class="bulleted-list"><li style="list-style-type:disc">Identify and remove malware, backdoors, or malicious files.</li></ul><ul id="1842c7d3-8aff-8040-8936-e79133319fdf" class="bulleted-list"><li style="list-style-type:disc">Patch exploited vulnerabilities in systems, software, or configurations.</li></ul><ul id="1842c7d3-8aff-8034-8831-e7d9b1b69f7c" class="bulleted-list"><li style="list-style-type:disc">Scan systems thoroughly to ensure no remnants of the attack remain.</li></ul><ul id="1842c7d3-8aff-808a-b76b-cea39ae25461" class="bulleted-list"><li style="list-style-type:disc">Harden systems and networks against similar attacks in the future.</li></ul></div></details></div></details><details open=""><summary style="font-weight:600;font-size:1.5em;line-height:1.3;margin:0"><mark class="highlight-teal_background">5.   </mark><mark class="highlight-teal_background"><strong>Recovery</strong></mark></summary><div class="indented"><blockquote id="1842c7d3-8aff-80a0-8f2b-cc69a22cdbd1" class="">The goal of this step is to restore normal operations while ensuring the environment is secure.</blockquote><details open=""><summary style="font-weight:600;font-size:1.5em;line-height:1.3;margin:0"><mark class="highlight-blue_background"><strong>Key Actions:</strong></mark></summary><div class="indented"><ul id="1842c7d3-8aff-80ce-a5bd-dd9a2da69518" class="bulleted-list"><li style="list-style-type:disc">Rebuild or restore affected systems from clean backups.</li></ul><ul id="1842c7d3-8aff-80db-91af-e6ff6b2ee1f0" class="bulleted-list"><li style="list-style-type:disc">Verify that all systems are functioning properly and securely.</li></ul><ul id="1842c7d3-8aff-804b-a970-edff2e3f4f03" class="bulleted-list"><li style="list-style-type:disc">Monitor systems closely for any signs of lingering threats.</li></ul><ul id="1842c7d3-8aff-8014-aa15-f11d5d67840d" class="bulleted-list"><li style="list-style-type:disc">Gradually reintroduce affected systems to the network.</li></ul></div></details></div></details><details open=""><summary style="font-weight:600;font-size:1.5em;line-height:1.3;margin:0"><mark class="highlight-teal_background">6. </mark><mark class="highlight-teal_background"><strong> Lessons Learned</strong></mark></summary><div class="indented"><blockquote id="1842c7d3-8aff-8055-9b8d-c62b7ff2dea0" class="">This final phase involves reviewing the incident to improve future responses and strengthen defenses.</blockquote><details open=""><summary style="font-weight:600;font-size:1.5em;line-height:1.3;margin:0"><mark class="highlight-blue_background"><strong>Key Actions:</strong></mark></summary><div class="indented"><ul id="1842c7d3-8aff-8075-962f-c69c5e973ead" class="bulleted-list"><li style="list-style-type:disc">Conduct a <strong>post-incident analysis</strong> with the incident response team.</li></ul><ul id="1842c7d3-8aff-80b5-83a2-f78959500f33" class="bulleted-list"><li style="list-style-type:disc">Document the root cause, timeline, response steps, and outcomes in an <strong>incident report</strong>.</li></ul><ul id="1842c7d3-8aff-80c6-9438-fcbd2b1fdd73" class="bulleted-list"><li style="list-style-type:disc">Update the Incident Response Plan (IRP) and playbooks based on lessons learned.</li></ul><ul id="1842c7d3-8aff-804b-aeaf-c94b9374ccc1" class="bulleted-list"><li style="list-style-type:disc">Implement additional security measures, such as stronger policies or better tools.</li></ul><ul id="1842c7d3-8aff-8031-a3e0-fbd34ebe02a9" class="bulleted-list"><li style="list-style-type:disc">Share findings with relevant stakeholders to promote awareness and understanding.</li></ul></div></details></div></details></div></details><p id="1842c7d3-8aff-8090-a183-f14ee7b05303" class="">
</p><hr id="1842c7d3-8aff-8014-8114-f919ce67ae4a"/><h1 id="1842c7d3-8aff-806b-98eb-ce9c91fe4152" class=""><mark class="highlight-blue_background"><strong>Simulated Malware Execution and Detection </strong></mark></h1><p id="1842c7d3-8aff-8041-9949-d20996ecff4c" class="">
</p><figure class="block-color-gray_background callout" style="white-space:pre-wrap;display:flex" id="1842c7d3-8aff-8024-9d0a-fb416148fdf8"><div style="font-size:1.5em"><span class="icon">➡️</span></div><div style="width:100%"><p id="1842c7d3-8aff-8081-886b-de39cf0a1f7b" class="">Network diagram for machines we have in our network that detect that attack from infected machine.</p></div></figure><figure id="1842c7d3-8aff-806e-b733-d575028e453b" class="image"><a href="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/20.png"><img style="width:707.984375px" src="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/20.png"/></a></figure><p id="1842c7d3-8aff-8087-82b1-eb45431c585c" class="">
</p><blockquote id="006e3ac5-c8bc-4428-91e6-8c7a207b1076" class=""><mark class="highlight-blue">This section details how we will execute the Zeus trojan simulation in a controlled environment while monitoring and logging its behavior. We will identify key compromise indicators and test detection methods.</mark></blockquote><blockquote id="7c263c94-03be-475a-9b77-7ffa823d18dc" class=""><mark class="highlight-blue">The simulation will follow strict security protocols to contain all malicious activities within our isolated testing environment. We will examine both attack methods and defense strategies.</mark></blockquote><p id="1842c7d3-8aff-809f-9272-fc987546de42" class="">
</p><figure class="block-color-gray_background callout" style="white-space:pre-wrap;display:flex" id="1842c7d3-8aff-8092-88b0-efaf85a76e51"><div style="font-size:1.5em"><span class="icon">➡️</span></div><div style="width:100%"><p id="1842c7d3-8aff-806f-b855-c00e3d3ebe78" class="">We are using a Windows 10 Enterprise Virtual Machine !</p></div></figure><figure id="1842c7d3-8aff-80fc-bde0-fc14ff45a13e" class="image"><a href="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/Picture1.png"><img style="width:672px" src="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/Picture1.png"/></a></figure><p id="1842c7d3-8aff-8071-8cea-ccd9f68df5af" class="">
</p><ol type="1" id="29f19dd8-968a-4ab1-aa80-2db2b46ad881" class="numbered-list" start="1"><li>Screenshot showing the Virtual Box configuration for the isolated testing environment. The VM is configured with limited resources and network access to prevent any potential malware escape.</li></ol><ol type="1" id="1842c7d3-8aff-8007-a35f-c2047a4d02ca" class="numbered-list" start="2"><li>We had an incident that detected from Alerts that match threat hunting rule from our soc team tuned rules that reviewed &amp; hardened as policy we have in our organization every 7 days.</li></ol><ol type="1" id="1842c7d3-8aff-808b-a5de-d56b5b5d857c" class="numbered-list" start="3"><li>Incident occurred from the user that violated the policy and installed file from untrusted sources that we defined before in our policy, because may be malicious and infect our machine then our network.</li></ol><ol type="1" id="1842c7d3-8aff-80f1-bedb-cd977ff365c4" class="numbered-list" start="4"><li>We receive alerts on our SIEM solution mainly from HIDS hosted on windows machine in our internal network.</li></ol><ol type="1" id="1842c7d3-8aff-8044-9936-ea4f97dc8a36" class="numbered-list" start="5"><li> Alert defines that machine interacts with malicious IP that match rule from tuned rules that we had written for hunting malware and suspicious actions on network machines.</li></ol><ol type="1" id="1842c7d3-8aff-805c-ba4d-dccf69c9d618" class="numbered-list" start="6"><li>Soc team receive alert from the Suricata HIDS Dashboard that we create before for more visibility About actions that acted on our network.</li></ol><p id="1842c7d3-8aff-8005-8225-ec75fcea216f" class="">
</p><figure class="block-color-gray_background callout" style="white-space:pre-wrap;display:flex" id="1842c7d3-8aff-80e8-a8bd-edcb5d597e1e"><div style="font-size:1.5em"><span class="icon">➡️</span></div><div style="width:100%"><h3 id="1842c7d3-8aff-80a6-8013-f8dbba153ef4" class="">Dashboard alert that we detect the incident from !</h3></div></figure><figure id="1842c7d3-8aff-80df-8560-f5aa3d3adb34" class="image"><a href="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/1.png"><img style="width:720px" src="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/1.png"/></a></figure><p id="a9145c1f-59fe-4664-a1fe-e972c9cbd1d0" class="">This dashboard alert shows critical security events detected by our Suricata HIDS system. It displays:</p><ul id="2fc9d74f-a196-492f-a1d1-e2688732fe07" class="bulleted-list"><li style="list-style-type:disc">Multiple high-severity alerts related to suspicious network traffic</li></ul><ul id="b7c00d53-f04f-4e80-a1c1-5cf08f5e7ca4" class="bulleted-list"><li style="list-style-type:disc">Timeline of detected malicious activities and connection attempts</li></ul><ul id="9dfa7d73-d3be-45ab-bf50-c8691f491b37" class="bulleted-list"><li style="list-style-type:disc">Source and destination IP addresses involved in the incident</li></ul><ul id="22a0d5d4-551d-4ab6-9b88-c25eb64ed0ab" class="bulleted-list"><li style="list-style-type:disc">Alert categories and classification of detected threats</li></ul><ul id="ebb193f7-3fe4-4260-b974-a2943645a14c" class="bulleted-list"><li style="list-style-type:disc">Timestamp information showing when suspicious activities occurred</li></ul><p id="b96d41f9-5ddb-42b3-a5ea-e61b258189b2" class="">The dashboard provides real-time visibility into potential security breaches and helps our SOC team quickly respond to threats.</p><p id="1842c7d3-8aff-80c6-a1fd-ce8afe7ce40e" class="">
</p><figure class="block-color-gray_background callout" style="white-space:pre-wrap;display:flex" id="1842c7d3-8aff-80aa-bb68-e9e0469f11c6"><div style="font-size:1.5em"><span class="icon">➡️</span></div><div style="width:100%"><p id="1842c7d3-8aff-8074-af4d-ce6258185a9d" class="">The Geo map for destination Ips that our machines interacted within the world Heated map!</p></div></figure><figure id="1842c7d3-8aff-80a7-8c44-e45319f81b6b" class="image"><a href="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/2.png"><img style="width:720px" src="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/2.png"/></a></figure><blockquote id="1842c7d3-8aff-80d1-b42c-c3749cc28bd7" class="">Our team hunt also massive amount of data transmitted to north America, mainly that not legit from base-line that our NBA (Network behavior data analytics) in our network .</blockquote><figure id="1842c7d3-8aff-8044-a7c2-ffe71d512b30" class="image"><a href="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/cyber_risks.png"><img style="width:768px" src="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/cyber_risks.png"/></a></figure><hr id="1842c7d3-8aff-80e0-8a7f-f83f1bf202e5"/><p id="1842c7d3-8aff-80f7-95ef-e72cf0e490cc" class="">
</p><figure class="block-color-gray_background callout" style="white-space:pre-wrap;display:flex" id="1842c7d3-8aff-803d-9a65-f13b7916626f"><div style="font-size:1.5em"><span class="icon">➡️</span></div><div style="width:100%"><h2 id="1842c7d3-8aff-8031-927e-f18a1f1dc8e9" class=""><strong>Start investigation for suspicious activity  that we get from HIDS alert !</strong></h2></div></figure><figure id="1842c7d3-8aff-80bc-8ff6-f102ea6bf5bd" class="image"><a href="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/3.png"><img style="width:707.9921875px" src="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/3.png"/></a></figure><ol type="1" id="1842c7d3-8aff-8033-a7e1-ca76cd37b30e" class="numbered-list" start="1"><li>From our alert that fired from malicious activity we detect the machine that cause that action (<mark class="highlight-blue_background">DESKTOP-9QMM40J</mark>)  this will be the root cause of the incident until we prove that that alert is false positive.</li></ol><p id="1842c7d3-8aff-807e-b4f4-f1f3a5e0a9c4" class="">
</p><figure class="block-color-gray_background callout" style="white-space:pre-wrap;display:flex" id="1842c7d3-8aff-807b-87ec-d3376b92fd52"><div style="font-size:1.5em"><span class="icon">➡️</span></div><div style="width:100%"><h2 id="1842c7d3-8aff-800f-abb1-cd5b96e8a473" class="">Start retrieve all event logs that relate to the machine that fire that alert!</h2></div></figure><figure id="1842c7d3-8aff-80e8-a951-d99b0d96cb92" class="image"><a href="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/4.png"><img style="width:707.9765625px" src="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/4.png"/></a></figure><p id="1842c7d3-8aff-80ed-ad8e-e763a4a67962" class="">
</p><figure class="block-color-gray_background callout" style="white-space:pre-wrap;display:flex" id="1842c7d3-8aff-80b1-a16a-fb15455c3b6f"><div style="font-size:1.5em"><span class="icon">➡️</span></div><div style="width:100%"><h2 id="1842c7d3-8aff-80d9-81ad-f30caee261aa" class="">Get our sources that machine depends on to push logs to our management node (SIEM)!</h2></div></figure><figure id="1842c7d3-8aff-80cf-b6fa-df36e68d9b86" class="image"><a href="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/5.png"><img style="width:707.9765625px" src="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/5.png"/></a></figure><p id="1842c7d3-8aff-80f5-8984-ceabdec0c26b" class="">
</p><figure class="block-color-gray_background callout" style="white-space:pre-wrap;display:flex" id="1842c7d3-8aff-80a8-9076-dd23ca11161d"><div style="font-size:1.5em"><span class="icon">➡️</span></div><div style="width:100%"><h2 id="1842c7d3-8aff-80d0-90fe-d26538800bd4" class="">We have to focus on specific log source to get tuned logs to detect the importance of the alert we get from HIDS and our source we relies on is Sysmon logs !</h2></div></figure><figure id="1842c7d3-8aff-806a-9b92-d40af8faae9e" class="image"><a href="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/6.png"><img style="width:707.9921875px" src="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/6.png"/></a></figure><p id="1842c7d3-8aff-80bb-88c8-c6b72b72f44f" class="">
</p><figure class="block-color-gray_background callout" style="white-space:pre-wrap;display:flex" id="1842c7d3-8aff-8089-92f3-fe254e150a76"><div style="font-size:1.5em"><span class="icon">➡️</span></div><div style="width:100%"><h2 id="1842c7d3-8aff-8091-80c8-f9b9f8b1111e" class="">We get all events that Sysmon log Source hunt from the infected machine and push throw universal forwarder !</h2></div></figure><figure id="1842c7d3-8aff-80dc-b32d-fdaebd1d9b63" class="image"><a href="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/9.png"><img style="width:720px" src="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/9.png"/></a></figure><p id="1842c7d3-8aff-8082-bfb4-e417ca45b60d" class="">
</p><figure class="block-color-gray_background callout" style="white-space:pre-wrap;display:flex" id="1842c7d3-8aff-80fb-9949-f82270c74b65"><div style="font-size:1.5em"><span class="icon">➡️</span></div><div style="width:100%"><h2 id="1842c7d3-8aff-8038-a24f-f09edc6dc7db" class="">We must tunning our search query to get more information about the exact alert related events. </h2><h2 id="1842c7d3-8aff-8020-99d7-eaa370dea5ec" class="">So, we limit the time interval to get the least number of events to investigate into.</h2></div></figure><figure id="1842c7d3-8aff-8025-b08a-d4fea9f3361c" class="image"><a href="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/10.png"><img style="width:2866px" src="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/10.png"/></a></figure><p id="1842c7d3-8aff-803a-957f-f2a5e0d8866f" class="">
</p><figure class="block-color-gray_background callout" style="white-space:pre-wrap;display:flex" id="1842c7d3-8aff-8068-b566-c7dff75f0f71"><div style="font-size:1.5em"><span class="icon">➡️</span></div><div style="width:100%"><h3 id="1842c7d3-8aff-8039-8923-f089e7182566" class="">We focus on processes that created by the machine user (<strong>saber</strong>) to be more knowledgeable about action that user took, then we hunt specific process with bad extension for obfuscation security controls of the organization (<mark class="highlight-blue_background"><strong>.pdf.exe</strong></mark>)! </h3></div></figure><figure id="1842c7d3-8aff-8069-95a9-c8a9c349f928" class="image"><a href="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/11.png"><img style="width:720px" src="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/11.png"/></a></figure><p id="1842c7d3-8aff-8018-a8b5-c732c0934d5f" class="">
</p><figure class="block-color-gray_background callout" style="white-space:pre-wrap;display:flex" id="1842c7d3-8aff-8092-b0ea-d4042c6fd5b2"><div style="font-size:1.5em"><span class="icon">➡️</span></div><div style="width:100%"><p id="1842c7d3-8aff-8071-ac41-fb75886bda08" class="">We have to investigate more depth with events related to that process to be insightful with details the Sysmon monitoring services provide, so we get 5 events we must be careful in that events investigation!</p></div></figure><figure id="1842c7d3-8aff-8068-bf97-dd53217d02f9" class="image"><a href="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/12.png"><img style="width:2867px" src="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/12.png"/></a></figure><p id="1842c7d3-8aff-80ad-8f41-fc42b2e3e06e" class="">
</p><figure class="block-color-gray_background callout" style="white-space:pre-wrap;display:flex" id="1842c7d3-8aff-80ca-be1e-d77337145fc1"><div style="font-size:1.5em"><span class="icon">➡️</span></div><div style="width:100%"><p id="1842c7d3-8aff-8040-8cd2-ef4e755cdf6b" class="">Our team exploit Sysmon features the service of calculate the hash for the process that created and files that the user modified or accessed, that add insightful information for analysts to detect which file be malicious or not with the use of Threat Intel tools like Virus Total that will be used in our investigation.</p></div></figure><figure id="1842c7d3-8aff-80f6-91a8-db998ec9041d" class="image"><a href="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/13.png"><img style="width:2392px" src="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/13.png"/></a></figure><p id="1842c7d3-8aff-8000-99e8-db0b742712e7" class="">
</p><figure class="block-color-gray_background callout" style="white-space:pre-wrap;display:flex" id="1842c7d3-8aff-8087-ae0d-d22eb0cc378a"><div style="font-size:1.5em"><span class="icon">➡️</span></div><div style="width:100%"><h2 id="1842c7d3-8aff-80ba-8076-f3a1ed989243" class="">Mainly from event that Sysmon pushed to SIEM, we have the file (<strong>pdf.exe</strong>) recorded and its relevant information like Hash with many algorithms!</h2></div></figure><figure id="1842c7d3-8aff-809c-aa79-db73907e2a2f" class="image"><a href="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/14.png"><img style="width:707.96875px" src="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/14.png"/></a></figure><p id="1842c7d3-8aff-80b5-b6e6-ec656ea14c97" class="">
</p><figure class="block-color-gray_background callout" style="white-space:pre-wrap;display:flex" id="1842c7d3-8aff-8060-bfe5-d57ba76c19ae"><div style="font-size:1.5em"><span class="icon">➡️</span></div><div style="width:100%"><h2 id="1842c7d3-8aff-801d-b863-c620b40224fb" class="">Get that file hash to be investigated in our Threat Intel (<mark class="highlight-blue_background">Virus Total</mark>)!</h2></div></figure><figure id="1842c7d3-8aff-80e2-924f-d3eca6edb5f4" class="image"><a href="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/15.png"><img style="width:707.96875px" src="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/15.png"/></a></figure><p id="1842c7d3-8aff-80cc-96a8-eaa0721bbeec" class="">
</p><figure class="block-color-gray_background callout" style="white-space:pre-wrap;display:flex" id="1842c7d3-8aff-807e-88ad-f9f265cdf261"><div style="font-size:1.5em"><span class="icon">➡️</span></div><div style="width:100%"><h2 id="1842c7d3-8aff-8069-bdfb-f54235097389" class="">Investigate the hash on our Threat intel VT !</h2></div></figure><figure id="1842c7d3-8aff-80e2-8686-e10fb8d742b2" class="image"><a href="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/16.png"><img style="width:2868px" src="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/16.png"/></a></figure><p id="1842c7d3-8aff-8078-80c8-fb498af12c44" class="">
</p><ol type="1" id="1842c7d3-8aff-8022-a7d5-fbc8d147f21d" class="numbered-list" start="1"><li>The analysis of the file (<mark class="highlight-blue_background"><strong>invoice_2318362983713_823931342io.</strong></mark><mark class="highlight-blue_background"> </mark><mark class="highlight-blue_background"><strong>pdf.exe)</strong></mark> with the hash <mark class="highlight-blue_background"><strong>69e966e730557fde8fd84317cdef1ece00a8bb3470c0b58f3231e170168af169</strong></mark><mark class="highlight-blue_background"> </mark>revealed it to be highly malicious. Detected by <strong>63 out of 72 security vendors</strong>, it is categorized as a <strong>Trojan</strong> and identified with labels such as <strong>ZAccess</strong>, <strong>Sirefef</strong>, and <strong>WLDRC</strong>. This file exhibits behaviors like persistence mechanisms, suspicious UDP activity, and anti-debugging techniques, indicating a sophisticated threat capable of maintaining access and evading detection.</li></ol><ol type="1" id="1842c7d3-8aff-80de-bd29-e787d1c7b476" class="numbered-list" start="2"><li>The detection of this file highlights the importance of proactive threat detection and response mechanisms, including file analysis, endpoint monitoring, and the implementation of strict email and file download security controls. This threat should be considered highly dangerous, and additional steps, such as blocking the hash and related domains, should be taken to prevent further incidents.</li></ol><ol type="1" id="1842c7d3-8aff-8097-8846-d2a99989fdb9" class="numbered-list" start="3"><li>This results from threat intel that prove true positive incident in our network, and we must create ticket in Incident Management Agent to move to the next stage (<mark class="highlight-blue_background"><strong>Incident Response Process</strong></mark>).</li></ol><p id="1842c7d3-8aff-80a2-ad5a-fa665598a16d" class="">
</p><figure class="block-color-gray_background callout" style="white-space:pre-wrap;display:flex" id="1842c7d3-8aff-8079-93ba-dc579e268edb"><div style="font-size:1.5em"><span class="icon">➡️</span></div><div style="width:100%"><p id="1842c7d3-8aff-8090-9061-c80580fa1366" class="">Suricata rule that hosted on infected machine that hunt the malicious file when executed and interact with malicious DNS server.</p></div></figure><figure id="1842c7d3-8aff-8093-89c8-c933e5c5d7e9" class="image"><a href="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/21.png"><img style="width:707.984375px" src="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/21.png"/></a></figure><p id="1842c7d3-8aff-8061-a9f9-eae61ff686e7" class="">
</p><figure class="block-color-gray_background callout" style="white-space:pre-wrap;display:flex" id="1842c7d3-8aff-807f-a08f-e34838677c8a"><div style="font-size:1.5em"><span class="icon">➡️</span></div><div style="width:100%"><h2 id="1842c7d3-8aff-8016-b865-e4ff2f765f2a" class="">Digital forensics process in the process of incident response plan ! </h2></div></figure><p id="1842c7d3-8aff-8066-97ca-f4227dbe3748" class="">
</p><blockquote id="1842c7d3-8aff-806c-882f-f395807e9b49" class=""><mark class="highlight-blue_background"><strong>Memory dump investigation with Volatility &amp; Yara Rules </strong></mark></blockquote><p id="1842c7d3-8aff-8057-9f93-dd395c14cb12" class="">
</p><ul id="1842c7d3-8aff-8036-8888-e148fe1c4886" class="bulleted-list"><li style="list-style-type:disc">At first, I used “imageinfo” to show information of this dump.</li></ul><figure id="1842c7d3-8aff-8057-ad2f-c13f313d6de6" class="image"><a href="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/image.png"><img style="width:707.984375px" src="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/image.png"/></a></figure><p id="1842c7d3-8aff-8000-813d-feee8787ba07" class="">
</p><ul id="1842c7d3-8aff-805b-a60e-ce9c278ee74b" class="bulleted-list"><li style="list-style-type:disc">We’re going to use the “WinXPSP2x86” profile in the following steps. Let’s then start by showing process list using “pslist”.</li></ul><figure id="1842c7d3-8aff-8093-b216-f86046182e31" class="image"><a href="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/image%201.png"><img style="width:707.984375px" src="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/image%201.png"/></a></figure><p id="1842c7d3-8aff-80dc-b000-d21e1b68927f" class="">
</p><ul id="1842c7d3-8aff-8041-b14f-f41160a22669" class="bulleted-list"><li style="list-style-type:disc">By looking at the process we can see that some are legit like “explorer.exe”, “winlogon.exe”, “services.exe”, and so on. But some of them look suspicious, like “b98679df6defbb3”, and with the existence of “ImmunityDebugger” we can guess that there was some sort of analysis running there. Let’s look further into these processes. I am going to look for processes that was run by ImmunityDebugger. There are multiple instances of it so we’re going through each one.</li></ul><figure id="1842c7d3-8aff-808f-a8ad-e17faaa42d91" class="image"><a href="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/p1.png"><img style="width:707.9921875px" src="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/p1.png"/></a></figure><figure id="1842c7d3-8aff-802b-bcad-fdabfbc14c33" class="image"><a href="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/Screenshot_2025-01-23_175320.png"><img style="width:707.984375px" src="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/Screenshot_2025-01-23_175320.png"/></a></figure><p id="1842c7d3-8aff-8095-942c-d99b39ed2b35" class="">
</p><ul id="1842c7d3-8aff-8053-a16d-ec9afbebbf12" class="bulleted-list"><li style="list-style-type:disc">As we can see above, there are some suspected files in this case “nifek_locked.ex”, “vaelh.exe”, “anaxu.exe”, “b98679df6defbb3”, and “ihah.exe”. Next step, we’re going to use “filescan” to look for these files.</li></ul><figure id="1842c7d3-8aff-80d4-abad-cf5c3465b9c8" class="image"><a href="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/90.png"><img style="width:707.9921875px" src="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/90.png"/></a></figure><p id="1842c7d3-8aff-806b-bc8d-f8c9db800914" class="">
</p><ul id="1842c7d3-8aff-80f7-89c0-c3b626169446" class="bulleted-list"><li style="list-style-type:disc">From the point of view, we can’t really tell if they are malicious or not. But, by observing the “b98679df6defbb3”, we can see here that it seems to be a hash digest. So, let’s pass it to Virus Total and look for any suspicion. And it’s indeed malicious with score 46/54.</li></ul><figure id="1842c7d3-8aff-80a6-8fa9-c52de13aacd5" class="image"><a href="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/91.png"><img style="width:707.9921875px" src="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/91.png"/></a></figure><p id="1842c7d3-8aff-80da-9226-e040039cf7c3" class="">
</p><ul id="1842c7d3-8aff-8043-a3bf-e2452086342a" class="bulleted-list"><li style="list-style-type:disc">Now I’m going to look for information about this file through “handles” module.</li></ul><figure id="1842c7d3-8aff-80ff-82da-f483e1b874f4" class="image"><a href="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/92.png"><img style="width:707.984375px" src="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/92.png"/></a></figure><p id="1842c7d3-8aff-80b2-b550-e76079c9a038" class="">
</p><p id="1842c7d3-8aff-8098-88ea-c1f25ea931e8" class="">As we can see, the “MACHINE\SYSTEM\CONTROLSET001\SERVICES\WINSOCK2\PARAME<br/>TERS\PROTOCOL_CATALOG9” can be an indicator of some kind of network interaction. Let’s run “connscan” and see if we can find any suspicious IP addresses.<br/></p><figure id="1842c7d3-8aff-8021-b4af-e48fd0a8846a" class="image"><a href="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/bafe7fd5-57fe-4c29-b97a-e63bc2d68db5.png"><img style="width:708px" src="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/bafe7fd5-57fe-4c29-b97a-e63bc2d68db5.png"/></a></figure><p id="1842c7d3-8aff-80a0-bc23-dcf0422f3ae0" class="">
</p><ul id="1842c7d3-8aff-803b-ba71-c4250df48f4d" class="bulleted-list"><li style="list-style-type:disc">Here we can see that there are three IP addresses, two of them is associated with Pid 1084 which is svchost service, and the last is associated with Pid 1752 which is explorer. Let’s use scamalytics to see if they indicate any risk.</li></ul><figure id="1842c7d3-8aff-80fa-966c-c18db1b7fa44" class="image"><a href="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/94.png"><img style="width:672px" src="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/94.png"/></a></figure><figure id="1842c7d3-8aff-80d4-bad7-e371b7964dfa" class="image"><a href="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/95.png"><img style="width:672px" src="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/95.png"/></a></figure><figure id="1842c7d3-8aff-809b-b8ed-eb4af8bb5b48" class="image"><a href="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/96.png"><img style="width:672px" src="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/96.png"/></a></figure><p id="1842c7d3-8aff-80e2-ae83-c800aeab46dd" class="">
</p><ul id="1842c7d3-8aff-80d3-9ad7-dbe7439dc34d" class="bulleted-list"><li style="list-style-type:disc">It looks like “193.43.134.14” has a medium fraud score, let’s pass it to virus total just to make sure that we are on the right track.</li></ul><figure id="1842c7d3-8aff-80af-9b00-d0672f8ff8dc" class="image"><a href="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/98.png"><img style="width:707.9921875px" src="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/98.png"/></a></figure><p id="1842c7d3-8aff-8043-bb45-f10ba11830ed" class="">
</p><ul id="1842c7d3-8aff-8017-afde-f6ad181c8371" class="bulleted-list"><li style="list-style-type:disc">Now, we can conclude that this IP is malicious according to Virus Total. If we navigate to the Relations tab, we’ll see the following</li></ul><figure id="1842c7d3-8aff-80cd-a1f1-e1264cb66a61" class="image"><a href="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/99.png"><img style="width:707.9921875px" src="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/99.png"/></a></figure><p id="1842c7d3-8aff-8046-b66b-f059c0d67df4" class="">
</p><ul id="1842c7d3-8aff-8028-99e5-e7d9507b8391" class="bulleted-list"><li style="list-style-type:disc">One of the files-Referring is 3772.dmp which is the process’s ID, the other is Wefietrenuyz which if we look back at the malicious file’s details, we’ll see it there.</li></ul><figure id="1842c7d3-8aff-800f-989f-c13c33d07327" class="image"><a href="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/image%202.png"><img style="width:672px" src="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/image%202.png"/></a></figure><p id="1842c7d3-8aff-80bf-bb22-c4083a05642d" class="">
</p><ul id="1842c7d3-8aff-8018-927a-c748c8dfe1eb" class="bulleted-list"><li style="list-style-type:disc">Now let’s dump the suspicious processes and see if we can find anything interesting.</li></ul><figure id="1842c7d3-8aff-8001-96f9-e0f2447089f4" class="image"><a href="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/100.png"><img style="width:708px" src="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/100.png"/></a></figure><figure id="1842c7d3-8aff-8069-9e27-f7951ebec38f" class="image"><a href="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/101.png"><img style="width:707.984375px" src="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/101.png"/></a></figure><p id="1842c7d3-8aff-80d8-b945-fb55b0ed3ed0" class="">
</p><ul id="1842c7d3-8aff-800e-b16d-e9b85fa5fc47" class="bulleted-list"><li style="list-style-type:disc">I’ve tried using tools like exiftool, binwalk, pedis, and others. And I couldn’t resolve errors associated to these tools. </li></ul><figure id="1842c7d3-8aff-8019-83e7-d1030b4dde46" class="image"><a href="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/102.png"><img style="width:672px" src="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/102.png"/></a></figure><p id="1842c7d3-8aff-8047-bf54-dc13e8dd5739" class="">
</p><ul id="1842c7d3-8aff-8026-9d79-ea2c8d805213" class="bulleted-list"><li style="list-style-type:disc">We can pass these dump files to virus total and see if they indicate to any malicious content. z</li></ul><figure id="1842c7d3-8aff-8078-87bb-d3d4c08504e9" class="image"><a href="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/201.png"><img style="width:707.9921875px" src="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/201.png"/></a></figure><p id="1842c7d3-8aff-806d-b046-fdc843a8a1e6" class="">
</p><figure id="1842c7d3-8aff-8084-843c-c1e476d0658b" class="image"><a href="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/202.png"><img style="width:707.9921875px" src="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/202.png"/></a></figure><p id="1842c7d3-8aff-8044-9fd5-c9170b356251" class="">
</p><figure id="1842c7d3-8aff-80d7-a61b-c1ef2cbde537" class="image"><a href="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/203.png"><img style="width:707.9921875px" src="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/203.png"/></a></figure><p id="1842c7d3-8aff-80a0-9c1e-c03a04c02626" class="">
</p><ul id="1842c7d3-8aff-8067-b122-e59a043ce6b5" class="bulleted-list"><li style="list-style-type:disc">From here we can conclude that these processes are malicious. If we take a look at the Details of Process 2204, Process 3276, and Process 952 under the Names Tab we can see that it detected their names.</li></ul><figure id="1842c7d3-8aff-8090-973b-dd6ee1f0944a" class="image"><a href="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/205.png"><img style="width:672px" src="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/205.png"/></a></figure><figure id="1842c7d3-8aff-80ba-abe4-fd8004e5c69c" class="image"><a href="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/206.png"><img style="width:672px" src="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/206.png"/></a></figure><figure id="1842c7d3-8aff-80db-bf75-c053ea563cd7" class="image"><a href="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/207.png"><img style="width:672px" src="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/207.png"/></a></figure><p id="1842c7d3-8aff-8090-8ef6-c90f52e6cbef" class="">
</p><details open=""><summary style="font-weight:600;font-size:1.875em;line-height:1.3;margin:0"><mark class="highlight-teal_background"><strong>Yara</strong></mark></summary><div class="indented"><p id="1842c7d3-8aff-8066-bb5b-dd1ce1c0d432" class="">
</p><blockquote id="1842c7d3-8aff-80db-9430-dd25f7f8a55c" class=""><mark class="highlight-blue_background">To use yara tool, we need to have a set of pre-defined rules called yara rules. And for that we’re going to use yarGen from previous labs. By using yarGen we’ll be able to generate our yara rules. I’ve setup yarGen before and all we need to do is generate the rules. Here we have the malware.</mark></blockquote><p id="1842c7d3-8aff-805f-871f-f5862d96a75a" class="">
</p><figure id="1842c7d3-8aff-8074-bb8a-ea0fc5e4fa54" class="image"><a href="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/208.png"><img style="width:679.9921875px" src="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/208.png"/></a></figure><p id="1842c7d3-8aff-806c-9ede-da67654b65c3" class="">
</p><ul id="1842c7d3-8aff-8067-be4e-f02b5e7db474" class="bulleted-list"><li style="list-style-type:disc">Let’s navigate to yarGen’s file path.</li></ul><figure id="1842c7d3-8aff-80e8-af35-ec01a7620685" class="image"><a href="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/image%203.png"><img style="width:679.9921875px" src="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/image%203.png"/></a></figure><p id="1842c7d3-8aff-80cd-a0d4-cc2b3a37823e" class="">
</p><ul id="1842c7d3-8aff-808d-918e-d22bd507d48c" class="bulleted-list"><li style="list-style-type:disc">And start generating the rules.</li></ul><figure id="1842c7d3-8aff-80bb-8e96-d6cff653be91" class="image"><a href="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/209.png"><img style="width:680px" src="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/209.png"/></a></figure><p id="1842c7d3-8aff-80b5-a31e-d9f96ae3e315" class="">
</p><ul id="1842c7d3-8aff-8038-91ac-edbdf05110c8" class="bulleted-list"><li style="list-style-type:disc">As we have our rules, now we can use yara to look for anomalies in the malware</li></ul><figure id="1842c7d3-8aff-8063-a268-cfd218d9df5e" class="image"><a href="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/210.png"><img style="width:679.9921875px" src="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/210.png"/></a></figure><figure id="1842c7d3-8aff-80a9-85a5-feb157a5ec67" class="image"><a href="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/mission-accomplished-nju2i8.jpg"><img style="width:672px" src="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/mission-accomplished-nju2i8.jpg"/></a></figure><p id="1842c7d3-8aff-80de-b59b-ca6a6a26bdd9" class="">
</p><p id="1842c7d3-8aff-80c5-b3cb-fa1f69e1ed5e" class="">
</p><figure class="block-color-gray_background callout" style="white-space:pre-wrap;display:flex" id="1842c7d3-8aff-800c-a91a-eb1b19982270"><div style="font-size:1.5em"><span class="icon">➡️</span></div><div style="width:100%"><h2 id="1842c7d3-8aff-8011-b746-c8f26553202e" class=""><strong>Malware analysis with sand Boxing (Any Run) for IOCs </strong>    <strong>enrichment</strong>  <strong>!</strong></h2></div></figure><ul id="1842c7d3-8aff-801c-b639-d21d2caef6cd" class="bulleted-list"><li style="list-style-type:disc"><strong>Once we upload the executable file that caused the incident and affect our system and infect the machine by the user (Saber) that download the malware and run it on the machine.</strong></li></ul><p id="1842c7d3-8aff-8026-b210-f27e8de0cf0b" class=""><br/>•  <br/><strong>The machine directly infected by running the malware we upload, the malware run on the machine and create sup-Processes to enforce the persistence on the machine and directly remove itself.</strong></p><figure id="1842c7d3-8aff-80fa-9434-ffcd211d6aae" class="image"><a href="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/24.png"><img style="width:707.9921875px" src="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/24.png"/></a></figure><p id="1842c7d3-8aff-80b8-b211-e7d16f439705" class=""><br/>•  We hunt all Http Requests from all processes that created from the parent to all decedent processes to get html document from servers that malicious processes interacted with them before.<br/></p><figure id="1842c7d3-8aff-8090-b439-c1d652e9eb60" class="image"><a href="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/image%204.png"><img style="width:720px" src="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/image%204.png"/></a></figure><p id="1842c7d3-8aff-80b7-afdb-cfc0717259d8" class="">
</p><p id="1842c7d3-8aff-808e-a418-ea938552edd2" class=""><br/>•  Get all connection that all processes with both ( <br/><strong>TCP &amp; UDP</strong> ) connection for all application layer protocols that run with mal-processes.</p><figure id="1842c7d3-8aff-8022-9c99-ca5d5f938027" class="image"><a href="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/25.png"><img style="width:707.9921875px" src="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/25.png"/></a></figure><p id="1842c7d3-8aff-806b-a9fe-d4090f4d6d9a" class=""><br/>•  Get all DNS records that all processes resolve the names to IPs.<br/></p><figure id="1842c7d3-8aff-8083-8246-f1106d8a6018" class="image"><a href="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/27.png"><img style="width:707.9921875px" src="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/27.png"/></a></figure><p id="1842c7d3-8aff-80b6-acf4-fdbcf7d3cf24" class=""><br/>•  Get all threats that the Sandbox detect from the dataset of IOCs for hunt threats of the malicious files. <br/></p><figure id="1842c7d3-8aff-802a-95b5-e11f3c8e6a1f" class="image"><a href="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/28.png"><img style="width:707.9765625px" src="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/28.png"/></a></figure><p id="1842c7d3-8aff-8015-ac8d-d0f1fc76fce5" class="">
</p><p id="1842c7d3-8aff-808f-a49d-e45bdb1220cb" class=""><br/>•  Sandbox marks the <br/><strong>exe as the most malicious process created from the malicious process installed by Saber-User.</strong></p><figure id="1842c7d3-8aff-8039-a541-c72ec7ef4ccc" class="image"><a href="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/29.png"><img style="width:707.984375px" src="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/29.png"/></a></figure><p id="1842c7d3-8aff-80a5-ba64-cda6539fe30e" class="">
</p><figure id="1842c7d3-8aff-8080-a023-c06b110e6cf6" class="image"><a href="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/30.png"><img style="width:707.9765625px" src="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/30.png"/></a></figure><p id="1842c7d3-8aff-80e0-a180-ec284a2ef073" class="">
</p><p id="1842c7d3-8aff-8020-815a-d3bdba4e589e" class=""><br/>•  The process that marked 100% malicious process, this process modify files to execute persistence for more information about the network to execute letteral movement on the network and infect more devices to steal credentials of whole network.<br/></p><figure id="1842c7d3-8aff-8070-a036-d7d962474a80" class="image"><a href="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/32.png"><img style="width:707.9921875px" src="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/32.png"/></a></figure><p id="1842c7d3-8aff-8094-8189-f8f526809e8a" class="">
</p><h3 id="1842c7d3-8aff-8047-8266-f8c8e1614a53" class=""><br/><br/><mark class="highlight-blue_background">•  </mark><mark class="highlight-blue_background"><strong>At this context we have to start Eradication process to remove all infected files from the machine and recover the system to normal state.</strong></mark></h3><h3 id="1842c7d3-8aff-80ac-9657-ea7d1836eff4" class=""><br/><br/><mark class="highlight-blue_background"><strong>•  Lesson learned from that attack is to harden the policies on the users more and more to ensure the users do not violate the rules for further security complexity.</strong></mark></h3><p id="1842c7d3-8aff-80e3-87a8-faffa0385163" class="">
</p><figure class="block-color-gray_background callout" style="white-space:pre-wrap;display:flex" id="1842c7d3-8aff-80c7-bc0d-e3d74576bc40"><div style="font-size:1.5em"><span class="icon">➡️</span></div><div style="width:100%"><h2 id="1842c7d3-8aff-8055-9085-ee6f1dde767b" class="">We have IOCs that we get from the incident:</h2></div></figure><figure id="1842c7d3-8aff-8046-ba8e-c979f21ad38e" class="image"><a href="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/image%205.png"><img style="width:707.9921875px" src="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/image%205.png"/></a></figure><p id="1842c7d3-8aff-8003-901a-cd3c6dfe1e5a" class="">
</p><figure id="1842c7d3-8aff-80ef-aa3f-cbc3d64927f0" class="image"><a href="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/image%206.png"><img style="width:679.9921875px" src="Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/image%206.png"/></a></figure></div></details></div></article><span class="sans" style="font-size:14px;padding-top:2em"></span></body></html>
