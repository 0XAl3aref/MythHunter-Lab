<div>

![](Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/artbreeder-image-2025-01-18T10_35_39.306Z.jpeg){.page-cover-image
style="object-position:center 50%"}

# Zeus Banking Trojan Simulation {#zeus-banking-trojan-simulation .page-title}

</div>

::: page-body
# Overview {#178536e2-3f10-4de8-8e56-3b41746b5cfc}

Zeus (also known as Zbot) is a notorious banking trojan that targets
financial credentials and personal information. This simulation will
explore its behavior and detection methods.

------------------------------------------------------------------------

## Technical Analysis {#4676d582-ce84-4cf0-a5ee-6bce15873562}

-   Initial Infection Vector

```{=html}
<!-- -->
```
-   Command & Control Communication

```{=html}
<!-- -->
```
-   Data Exfiltration Methods

```{=html}
<!-- -->
```
-   Persistence Mechanisms

------------------------------------------------------------------------

## Detection Methods {#3244c61f-cac6-4d1a-a6a5-3ffbcd83e80f}

-   Network Traffic Analysis

```{=html}
<!-- -->
```
-   System Behavior Monitoring

```{=html}
<!-- -->
```
-   Memory Analysis

```{=html}
<!-- -->
```
-   Registry Changes

------------------------------------------------------------------------

## Simulation Components {#892512db-f6a5-496b-94e5-a673a1f2c64e}

-   ::: {.checkbox .checkbox-off}
    :::

    [Set up isolated testing environment]{.to-do-children-unchecked}

    ::: indented
    :::

```{=html}
<!-- -->
```
-   ::: {.checkbox .checkbox-off}
    :::

    [Configure network monitoring tools]{.to-do-children-unchecked}

    ::: indented
    :::

```{=html}
<!-- -->
```
-   ::: {.checkbox .checkbox-off}
    :::

    [Implement logging mechanisms]{.to-do-children-unchecked}

    ::: indented
    :::

```{=html}
<!-- -->
```
-   ::: {.checkbox .checkbox-off}
    :::

    [Prepare analysis tools]{.to-do-children-unchecked}

    ::: indented
    :::

::: {style="width:100%"}
Warning: This simulation is for educational purposes only. Never deploy
malware on production systems or networks.
:::

------------------------------------------------------------------------

## Expected Behaviors {#1842c7d3-8aff-80dd-b63c-c5886d6b8ef0}

The simulation will demonstrate:

-   Web injection techniques

```{=html}
<!-- -->
```
-   Form grabbing capabilities

```{=html}
<!-- -->
```
-   Man-in-the-browser attacks

```{=html}
<!-- -->
```
-   Keystroke logging

------------------------------------------------------------------------

## Safety Measures {#1842c7d3-8aff-8048-bb91-dc1199f444cc}

-   Use isolated virtual environment

```{=html}
<!-- -->
```
-   Implement network segmentation

```{=html}
<!-- -->
```
-   Monitor all traffic carefully

```{=html}
<!-- -->
```
-   Document all findings securely

------------------------------------------------------------------------

![](Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/300.png){style="width:707.984375px"}

Note: This diagram represents a general flow of how Zeus banking trojan
typically operates in attacking banking systems and the corresponding
security measures. Specific bank names are not included for security
reasons.

------------------------------------------------------------------------

Incident response process that will be executed for recovering system to
the normal mode is!

::: indented
[1. ]{.mark .highlight-teal_background}[**Preparation**]{.mark
.highlight-teal_background}

::: indented
> [ **This step involves setting up processes, tools, and resources to
> ensure an organization can effectively respond to incidents.**]{.mark
> .highlight-blue_background}

**Key Actions:**

::: indented
-   Develop and document an **Incident Response Plan (IRP)**.

```{=html}
<!-- -->
```
-   Establish an **Incident Response Team (IRT)** with defined roles and
    responsibilities.

```{=html}
<!-- -->
```
-   Deploy and configure security tools like SIEMs, EDRs, and firewalls.

```{=html}
<!-- -->
```
-   Train staff with **cybersecurity awareness** and conduct regular
    incident response drills (e.g., tabletop exercises).

```{=html}
<!-- -->
```
-   Maintain an updated **inventory of critical assets** and their
    associated risks.

```{=html}
<!-- -->
```
-   Develop playbooks for common attack scenarios (e.g., phishing,
    ransomware, data breaches).
:::
:::

[**2. Identification**]{.mark .highlight-teal_background}

::: indented
> In this phase, you detect and confirm potential security incidents by
> analyzing alerts, logs, and behaviors.

[**Key Actions:**]{.mark .highlight-blue_background}

::: indented
-   **Monitor systems** and networks using tools like SIEM, IDS/IPS, and
    endpoint security tools.

```{=html}
<!-- -->
```
-   Analyze alerts and anomalies to confirm if an incident is occurring.

```{=html}
<!-- -->
```
-   Gather forensic data, including logs, system snapshots, and network
    traffic.

```{=html}
<!-- -->
```
-   Classify and prioritize the incident based on its severity, impact,
    and type (e.g., phishing, ransomware).

```{=html}
<!-- -->
```
-   Answer critical questions:
    -   What happened?

    ```{=html}
    <!-- -->
    ```
    -   When did it occur?

    ```{=html}
    <!-- -->
    ```
    -   Who/what is impacted?

    ```{=html}
    <!-- -->
    ```
    -   What is the potential impact?
:::
:::

[3. ]{.mark .highlight-teal_background}[ **Containment**]{.mark
.highlight-teal_background}

::: indented
> This step focuses on stopping the spread of the attack and limiting
> its damage.

[**Key Actions:**]{.mark .highlight-blue_background}

::: indented
-   **Short-term containment**: Isolate affected systems (e.g., unplug
    from the network, disable accounts).

```{=html}
<!-- -->
```
-   **Long-term containment**: Set up temporary solutions, such as
    deploying new firewalls or network segments.

```{=html}
<!-- -->
```
-   Block malicious domains, IPs, and email addresses in firewalls or
    DNS settings.

```{=html}
<!-- -->
```
-   Implement patches or workarounds to prevent further exploitation.

```{=html}
<!-- -->
```
-   Preserve evidence for further investigation (e.g., disk images,
    memory dumps).
:::
:::

[4. ]{.mark .highlight-teal_background}[**Eradication**]{.mark
.highlight-teal_background}

::: indented
> In this phase, you remove the threat from your environment to prevent
> further compromise.

[**Key Actions:**]{.mark .highlight-blue_background}

::: indented
-   Identify and remove malware, backdoors, or malicious files.

```{=html}
<!-- -->
```
-   Patch exploited vulnerabilities in systems, software, or
    configurations.

```{=html}
<!-- -->
```
-   Scan systems thoroughly to ensure no remnants of the attack remain.

```{=html}
<!-- -->
```
-   Harden systems and networks against similar attacks in the future.
:::
:::

[5. ]{.mark .highlight-teal_background}[**Recovery**]{.mark
.highlight-teal_background}

::: indented
> The goal of this step is to restore normal operations while ensuring
> the environment is secure.

[**Key Actions:**]{.mark .highlight-blue_background}

::: indented
-   Rebuild or restore affected systems from clean backups.

```{=html}
<!-- -->
```
-   Verify that all systems are functioning properly and securely.

```{=html}
<!-- -->
```
-   Monitor systems closely for any signs of lingering threats.

```{=html}
<!-- -->
```
-   Gradually reintroduce affected systems to the network.
:::
:::

[6. ]{.mark .highlight-teal_background}[ **Lessons Learned**]{.mark
.highlight-teal_background}

::: indented
> This final phase involves reviewing the incident to improve future
> responses and strengthen defenses.

[**Key Actions:**]{.mark .highlight-blue_background}

::: indented
-   Conduct a **post-incident analysis** with the incident response
    team.

```{=html}
<!-- -->
```
-   Document the root cause, timeline, response steps, and outcomes in
    an **incident report**.

```{=html}
<!-- -->
```
-   Update the Incident Response Plan (IRP) and playbooks based on
    lessons learned.

```{=html}
<!-- -->
```
-   Implement additional security measures, such as stronger policies or
    better tools.

```{=html}
<!-- -->
```
-   Share findings with relevant stakeholders to promote awareness and
    understanding.
:::
:::
:::

------------------------------------------------------------------------

# [**Simulated Malware Execution and Detection** ]{.mark .highlight-blue_background} {#1842c7d3-8aff-806b-98eb-ce9c91fe4152}

::: {style="font-size:1.5em"}
[➡️]{.icon}
:::

::: {style="width:100%"}
Network diagram for machines we have in our network that detect that
attack from infected machine.
:::

![](Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/20.png){style="width:707.984375px"}

> [This section details how we will execute the Zeus trojan simulation
> in a controlled environment while monitoring and logging its behavior.
> We will identify key compromise indicators and test detection
> methods.]{.mark .highlight-blue}

> [The simulation will follow strict security protocols to contain all
> malicious activities within our isolated testing environment. We will
> examine both attack methods and defense strategies.]{.mark
> .highlight-blue}

::: {style="font-size:1.5em"}
[➡️]{.icon}
:::

::: {style="width:100%"}
We are using a Windows 10 Enterprise Virtual Machine !
:::

![](Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/Picture1.png){style="width:672px"}

1.  Screenshot showing the Virtual Box configuration for the isolated
    testing environment. The VM is configured with limited resources and
    network access to prevent any potential malware escape.

```{=html}
<!-- -->
```
2.  We had an incident that detected from Alerts that match threat
    hunting rule from our soc team tuned rules that reviewed & hardened
    as policy we have in our organization every 7 days.

```{=html}
<!-- -->
```
3.  Incident occurred from the user that violated the policy and
    installed file from untrusted sources that we defined before in our
    policy, because may be malicious and infect our machine then our
    network.

```{=html}
<!-- -->
```
4.  We receive alerts on our SIEM solution mainly from HIDS hosted on
    windows machine in our internal network.

```{=html}
<!-- -->
```
5.  Alert defines that machine interacts with malicious IP that match
    rule from tuned rules that we had written for hunting malware and
    suspicious actions on network machines.

```{=html}
<!-- -->
```
6.  Soc team receive alert from the Suricata HIDS Dashboard that we
    create before for more visibility About actions that acted on our
    network.

::: {style="font-size:1.5em"}
[➡️]{.icon}
:::

::: {style="width:100%"}
### Dashboard alert that we detect the incident from ! {#1842c7d3-8aff-80a6-8013-f8dbba153ef4}
:::

![](Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/1.png){style="width:720px"}

This dashboard alert shows critical security events detected by our
Suricata HIDS system. It displays:

-   Multiple high-severity alerts related to suspicious network traffic

```{=html}
<!-- -->
```
-   Timeline of detected malicious activities and connection attempts

```{=html}
<!-- -->
```
-   Source and destination IP addresses involved in the incident

```{=html}
<!-- -->
```
-   Alert categories and classification of detected threats

```{=html}
<!-- -->
```
-   Timestamp information showing when suspicious activities occurred

The dashboard provides real-time visibility into potential security
breaches and helps our SOC team quickly respond to threats.

::: {style="font-size:1.5em"}
[➡️]{.icon}
:::

::: {style="width:100%"}
The Geo map for destination Ips that our machines interacted within the
world Heated map!
:::

![](Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/2.png){style="width:720px"}

> Our team hunt also massive amount of data transmitted to north
> America, mainly that not legit from base-line that our NBA (Network
> behavior data analytics) in our network .

![](Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/cyber_risks.png){style="width:768px"}

------------------------------------------------------------------------

::: {style="font-size:1.5em"}
[➡️]{.icon}
:::

::: {style="width:100%"}
## **Start investigation for suspicious activity  that we get from HIDS alert !** {#1842c7d3-8aff-8031-927e-f18a1f1dc8e9}
:::

![](Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/3.png){style="width:707.9921875px"}

1.  From our alert that fired from malicious activity we detect the
    machine that cause that action ([DESKTOP-9QMM40J]{.mark
    .highlight-blue_background}) this will be the root cause of the
    incident until we prove that that alert is false positive.

::: {style="font-size:1.5em"}
[➡️]{.icon}
:::

::: {style="width:100%"}
## Start retrieve all event logs that relate to the machine that fire that alert! {#1842c7d3-8aff-800f-abb1-cd5b96e8a473}
:::

![](Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/4.png){style="width:707.9765625px"}

::: {style="font-size:1.5em"}
[➡️]{.icon}
:::

::: {style="width:100%"}
## Get our sources that machine depends on to push logs to our management node (SIEM)! {#1842c7d3-8aff-80d9-81ad-f30caee261aa}
:::

![](Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/5.png){style="width:707.9765625px"}

::: {style="font-size:1.5em"}
[➡️]{.icon}
:::

::: {style="width:100%"}
## We have to focus on specific log source to get tuned logs to detect the importance of the alert we get from HIDS and our source we relies on is Sysmon logs ! {#1842c7d3-8aff-80d0-90fe-d26538800bd4}
:::

![](Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/6.png){style="width:707.9921875px"}

::: {style="font-size:1.5em"}
[➡️]{.icon}
:::

::: {style="width:100%"}
## We get all events that Sysmon log Source hunt from the infected machine and push throw universal forwarder ! {#1842c7d3-8aff-8091-80c8-f9b9f8b1111e}
:::

![](Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/9.png){style="width:720px"}

::: {style="font-size:1.5em"}
[➡️]{.icon}
:::

::: {style="width:100%"}
## We must tunning our search query to get more information about the exact alert related events. {#1842c7d3-8aff-8038-a24f-f09edc6dc7db}

## So, we limit the time interval to get the least number of events to investigate into. {#1842c7d3-8aff-8020-99d7-eaa370dea5ec}
:::

![](Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/10.png){style="width:2866px"}

::: {style="font-size:1.5em"}
[➡️]{.icon}
:::

::: {style="width:100%"}
### We focus on processes that created by the machine user (**saber**) to be more knowledgeable about action that user took, then we hunt specific process with bad extension for obfuscation security controls of the organization ([**.pdf.exe**]{.mark .highlight-blue_background})! {#1842c7d3-8aff-8039-8923-f089e7182566}
:::

![](Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/11.png){style="width:720px"}

::: {style="font-size:1.5em"}
[➡️]{.icon}
:::

::: {style="width:100%"}
We have to investigate more depth with events related to that process to
be insightful with details the Sysmon monitoring services provide, so we
get 5 events we must be careful in that events investigation!
:::

![](Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/12.png){style="width:2867px"}

::: {style="font-size:1.5em"}
[➡️]{.icon}
:::

::: {style="width:100%"}
Our team exploit Sysmon features the service of calculate the hash for
the process that created and files that the user modified or accessed,
that add insightful information for analysts to detect which file be
malicious or not with the use of Threat Intel tools like Virus Total
that will be used in our investigation.
:::

![](Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/13.png){style="width:2392px"}

::: {style="font-size:1.5em"}
[➡️]{.icon}
:::

::: {style="width:100%"}
## Mainly from event that Sysmon pushed to SIEM, we have the file (**pdf.exe**) recorded and its relevant information like Hash with many algorithms! {#1842c7d3-8aff-80ba-8076-f3a1ed989243}
:::

![](Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/14.png){style="width:707.96875px"}

::: {style="font-size:1.5em"}
[➡️]{.icon}
:::

::: {style="width:100%"}
## Get that file hash to be investigated in our Threat Intel ([Virus Total]{.mark .highlight-blue_background})! {#1842c7d3-8aff-801d-b863-c620b40224fb}
:::

![](Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/15.png){style="width:707.96875px"}

::: {style="font-size:1.5em"}
[➡️]{.icon}
:::

::: {style="width:100%"}
## Investigate the hash on our Threat intel VT ! {#1842c7d3-8aff-8069-bdfb-f54235097389}
:::

![](Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/16.png){style="width:2868px"}

1.  The analysis of the file
    ([**invoice_2318362983713_823931342io.**]{.mark
    .highlight-blue_background}[ ]{.mark
    .highlight-blue_background}[**pdf.exe)**]{.mark
    .highlight-blue_background} with the hash
    [**69e966e730557fde8fd84317cdef1ece00a8bb3470c0b58f3231e170168af169**]{.mark
    .highlight-blue_background}[ ]{.mark
    .highlight-blue_background}revealed it to be highly malicious.
    Detected by **63 out of 72 security vendors**, it is categorized as
    a **Trojan** and identified with labels such as **ZAccess**,
    **Sirefef**, and **WLDRC**. This file exhibits behaviors like
    persistence mechanisms, suspicious UDP activity, and anti-debugging
    techniques, indicating a sophisticated threat capable of maintaining
    access and evading detection.

```{=html}
<!-- -->
```
2.  The detection of this file highlights the importance of proactive
    threat detection and response mechanisms, including file analysis,
    endpoint monitoring, and the implementation of strict email and file
    download security controls. This threat should be considered highly
    dangerous, and additional steps, such as blocking the hash and
    related domains, should be taken to prevent further incidents.

```{=html}
<!-- -->
```
3.  This results from threat intel that prove true positive incident in
    our network, and we must create ticket in Incident Management Agent
    to move to the next stage ([**Incident Response Process**]{.mark
    .highlight-blue_background}).

::: {style="font-size:1.5em"}
[➡️]{.icon}
:::

::: {style="width:100%"}
Suricata rule that hosted on infected machine that hunt the malicious
file when executed and interact with malicious DNS server.
:::

![](Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/21.png){style="width:707.984375px"}

::: {style="font-size:1.5em"}
[➡️]{.icon}
:::

::: {style="width:100%"}
## Digital forensics process in the process of incident response plan ! {#1842c7d3-8aff-8016-b865-e4ff2f765f2a}
:::

> [**Memory dump investigation with Volatility & Yara Rules** ]{.mark
> .highlight-blue_background}

-   At first, I used "imageinfo" to show information of this dump.

![](Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/image.png){style="width:707.984375px"}

-   We're going to use the "WinXPSP2x86" profile in the following steps.
    Let's then start by showing process list using "pslist".

![](Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/image%201.png){style="width:707.984375px"}

-   By looking at the process we can see that some are legit like
    "explorer.exe", "winlogon.exe", "services.exe", and so on. But some
    of them look suspicious, like "b98679df6defbb3", and with the
    existence of "ImmunityDebugger" we can guess that there was some
    sort of analysis running there. Let's look further into these
    processes. I am going to look for processes that was run by
    ImmunityDebugger. There are multiple instances of it so we're going
    through each one.

![](Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/p1.png){style="width:707.9921875px"}

![](Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/Screenshot_2025-01-23_175320.png){style="width:707.984375px"}

-   As we can see above, there are some suspected files in this case
    "nifek_locked.ex", "vaelh.exe", "anaxu.exe", "b98679df6defbb3", and
    "ihah.exe". Next step, we're going to use "filescan" to look for
    these files.

![](Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/90.png){style="width:707.9921875px"}

-   From the point of view, we can't really tell if they are malicious
    or not. But, by observing the "b98679df6defbb3", we can see here
    that it seems to be a hash digest. So, let's pass it to Virus Total
    and look for any suspicion. And it's indeed malicious with score
    46/54.

![](Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/91.png){style="width:707.9921875px"}

-   Now I'm going to look for information about this file through
    "handles" module.

![](Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/92.png){style="width:707.984375px"}

As we can see, the
"MACHINE\\SYSTEM\\CONTROLSET001\\SERVICES\\WINSOCK2\\PARAME\
TERS\\PROTOCOL_CATALOG9" can be an indicator of some kind of network
interaction. Let's run "connscan" and see if we can find any suspicious
IP addresses.\

![](Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/bafe7fd5-57fe-4c29-b97a-e63bc2d68db5.png){style="width:708px"}

-   Here we can see that there are three IP addresses, two of them is
    associated with Pid 1084 which is svchost service, and the last is
    associated with Pid 1752 which is explorer. Let's use scamalytics to
    see if they indicate any risk.

![](Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/94.png){style="width:672px"}

![](Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/95.png){style="width:672px"}

![](Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/96.png){style="width:672px"}

-   It looks like "193.43.134.14" has a medium fraud score, let's pass
    it to virus total just to make sure that we are on the right track.

![](Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/98.png){style="width:707.9921875px"}

-   Now, we can conclude that this IP is malicious according to Virus
    Total. If we navigate to the Relations tab, we'll see the following

![](Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/99.png){style="width:707.9921875px"}

-   One of the files-Referring is 3772.dmp which is the process's ID,
    the other is Wefietrenuyz which if we look back at the malicious
    file's details, we'll see it there.

![](Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/image%202.png){style="width:672px"}

-   Now let's dump the suspicious processes and see if we can find
    anything interesting.

![](Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/100.png){style="width:708px"}

![](Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/101.png){style="width:707.984375px"}

-   I've tried using tools like exiftool, binwalk, pedis, and others.
    And I couldn't resolve errors associated to these tools.

![](Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/102.png){style="width:672px"}

-   We can pass these dump files to virus total and see if they indicate
    to any malicious content. z

![](Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/201.png){style="width:707.9921875px"}

![](Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/202.png){style="width:707.9921875px"}

![](Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/203.png){style="width:707.9921875px"}

-   From here we can conclude that these processes are malicious. If we
    take a look at the Details of Process 2204, Process 3276, and
    Process 952 under the Names Tab we can see that it detected their
    names.

![](Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/205.png){style="width:672px"}

![](Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/206.png){style="width:672px"}

![](Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/207.png){style="width:672px"}

[**Yara**]{.mark .highlight-teal_background}

::: indented
> [To use yara tool, we need to have a set of pre-defined rules called
> yara rules. And for that we're going to use yarGen from previous labs.
> By using yarGen we'll be able to generate our yara rules. I've setup
> yarGen before and all we need to do is generate the rules. Here we
> have the malware.]{.mark .highlight-blue_background}

![](Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/208.png){style="width:679.9921875px"}

-   Let's navigate to yarGen's file path.

![](Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/image%203.png){style="width:679.9921875px"}

-   And start generating the rules.

![](Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/209.png){style="width:680px"}

-   As we have our rules, now we can use yara to look for anomalies in
    the malware

![](Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/210.png){style="width:679.9921875px"}

![](Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/mission-accomplished-nju2i8.jpg){style="width:672px"}

::: {style="font-size:1.5em"}
[➡️]{.icon}
:::

::: {style="width:100%"}
## **Malware analysis with sand Boxing (Any Run) for IOCs** **enrichment** **!** {#1842c7d3-8aff-8011-b746-c8f26553202e}
:::

-   **Once we upload the executable file that caused the incident and
    affect our system and infect the machine by the user (Saber) that
    download the malware and run it on the machine.**

\
•\
**The machine directly infected by running the malware we upload, the
malware run on the machine and create sup-Processes to enforce the
persistence on the machine and directly remove itself.**

![](Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/24.png){style="width:707.9921875px"}

\
• We hunt all Http Requests from all processes that created from the
parent to all decedent processes to get html document from servers that
malicious processes interacted with them before.\

![](Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/image%204.png){style="width:720px"}

\
• Get all connection that all processes with both (\
**TCP & UDP** ) connection for all application layer protocols that run
with mal-processes.

![](Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/25.png){style="width:707.9921875px"}

\
• Get all DNS records that all processes resolve the names to IPs.\

![](Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/27.png){style="width:707.9921875px"}

\
• Get all threats that the Sandbox detect from the dataset of IOCs for
hunt threats of the malicious files.\

![](Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/28.png){style="width:707.9765625px"}

\
• Sandbox marks the\
**exe as the most malicious process created from the malicious process
installed by Saber-User.**

![](Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/29.png){style="width:707.984375px"}

![](Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/30.png){style="width:707.9765625px"}

\
• The process that marked 100% malicious process, this process modify
files to execute persistence for more information about the network to
execute letteral movement on the network and infect more devices to
steal credentials of whole network.\

![](Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/32.png){style="width:707.9921875px"}

###   [• ]{.mark .highlight-blue_background}[**At this context we have to start Eradication process to remove all infected files from the machine and recover the system to normal state.**]{.mark .highlight-blue_background} {#1842c7d3-8aff-8047-8266-f8c8e1614a53}

###   [**• Lesson learned from that attack is to harden the policies on the users more and more to ensure the users do not violate the rules for further security complexity.**]{.mark .highlight-blue_background} {#1842c7d3-8aff-80ac-9657-ea7d1836eff4}

::: {style="font-size:1.5em"}
[➡️]{.icon}
:::

::: {style="width:100%"}
## We have IOCs that we get from the incident: {#1842c7d3-8aff-8055-9085-ee6f1dde767b}
:::

![](Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/image%205.png){style="width:707.9921875px"}

![](Zeus%20Banking%20Trojan%20Simulation%201152c7d38aff80e4b21ac9f3630d507f/image%206.png){style="width:679.9921875px"}
:::
:::

[]{.sans style="font-size:14px;padding-top:2em"}

