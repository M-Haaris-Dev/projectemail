import { Database } from "./database.js";
import { analyzeEmail } from "./pipeline.js";
import { geminiService } from "./gemini.js";

const ORIGINAL_EML = `Delivered-To: sm2315@cse.jgec.ac.in
Received: by 2002:a05:622a:54b:0:0:0:0 with SMTP id m11csp767951qtx;
        Thu, 24 Jun 2021 11:29:34 -0700 (PDT)
X-Received: by 2002:a17:906:b20d:: with SMTP id p13mr6592087ejz.519.1624559374423;
        Thu, 24 Jun 2021 11:29:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624559374; cv=none;
        d=google.com; s=arc-20160816;
        b=LimigOZWezUIRkn80vN0rHTTIFL33n4m6W5GmQGijQISIZfJJiaZ7hVu+2acrPsocc
ARC-Authentication-Results: i=1; mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025;
       spf=pass (google.com: domain of gr33nm0nk2802@gmail.com designates 209.85.220.41 as permitted sender) smtp.mailfrom=gr33nm0nk2802@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Return-Path: <gr33nm0nk2802@gmail.com>
Received: from mail-sor-f41.google.com (mail-sor-f41.google.com. [209.85.220.41])
        by mx.google.com with SMTPS id h9sor4356126edb.0.2021.06.24.11.29.34
        for <sm2315@cse.jgec.ac.in>
        (Google Transport Security);
        Thu, 24 Jun 2021 11:29:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of gr33nm0nk2802@gmail.com designates 209.85.220.41 as permitted sender) client-ip=209.85.220.41;
Authentication-Results: mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025;
       spf=pass (google.com: domain of gr33nm0nk2802@gmail.com designates 209.85.220.41 as permitted sender) smtp.mailfrom=gr33nm0nk2802@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:from:date:message-id:subject:to;
        bh=Xv/F6z3BMW+GDSDlgbxRNPkMIkTU1Cl99j2AH0xrWDM=;
        b=Yw1+pYvThcd8a+f664Dy71wGZ507CGM0XaY2WEbmQVnXvA4q8NLwNL3xD8Wp27CP3r
From: gr33n m0nk <gr33nm0nk2802@gmail.com>
Date: Thu, 24 Jun 2021 23:59:23 +0530
Message-ID: <CAAJrJcE30Gt05PaO6m_i8G_7qwBg67SBcmytrHNmLEL3Mo59iw@mail.gmail.com>
Subject: This is a test original mail subject
To: sm2315@cse.jgec.ac.in
Content-Type: multipart/alternative; boundary="0000000000006684f505c587347d"

--0000000000006684f505c587347d
Content-Type: text/plain; charset="UTF-8"

This is the original test mail body.

--0000000000006684f505c587347d--
`;

const SPOOFED_EML = `Delivered-To: gr33nm0nk2802@gmail.com
Received: by 2002:aa7:dd49:0:0:0:0:0 with SMTP id o9csp3855327edw;
        Mon, 21 Jun 2021 03:40:02 -0700 (PDT)
ARC-Authentication-Results: i=1; mx.google.com;
       spf=softfail (google.com: domain of transitioning sm2315@cse.jgec.ac.in does not designate 101.99.94.155 as permitted sender) smtp.mailfrom=sm2315@cse.jgec.ac.in
Return-Path: <sm2315@cse.jgec.ac.in>
Received: from emkei.cz (emkei.cz. [101.99.94.155])
        by mx.google.com with ESMTPS id f7si8905426edq.341.2021.06.21.03.40.02
        for <gr33nm0nk2802@gmail.com>;
        Mon, 21 Jun 2021 03:40:02 -0700 (PDT)
Received-SPF: softfail (google.com: domain of transitioning sm2315@cse.jgec.ac.in does not designate 101.99.94.155 as permitted sender) client-ip=101.99.94.155;
Authentication-Results: mx.google.com;
       spf=softfail (google.com: domain of transitioning sm2315@cse.jgec.ac.in does not designate 101.99.94.155 as permitted sender) smtp.mailfrom=sm2315@cse.jgec.ac.in
To: gr33nm0nk2802@gmail.com
Subject: =?UTF-8?B?V2hvYW1pPw==?=
From: "Syed Modassir Ali" <sm2315@cse.jgec.ac.in>
Reply-To: sm2315@cse.jgec.ac.in
Content-Type: text/plain; charset=utf-8
Message-Id: <20210621104002.186B924176@emkei.cz>
Date: Mon, 21 Jun 2021 12:40:02 +0200 (CEST)

This is a test to learn spoofing.
`;

const PHISHING_PAYPAL_EML = `Delivered-To: victim@example.com
Received: from unverified-vps.attacker.net ([185.220.101.45])
        by mx.customer-inbox.net with ESMTP id px9283741
        for <victim@example.com>;
        Wed, 14 Jul 2021 08:15:20 +0000
Return-Path: <bounce@unverified-vps.attacker.net>
Reply-To: security-team@paypal-support-verify-acc.net
From: "PayPal Security Dept" <support@notifications-online-sec.org>
To: victim@example.com
Subject: =?UTF-8?B?VElNRSBTRU5TSVRJVkU6IFlvdXIgUGF5UGFsIGFjY291bnQgaGFzIGJlZW4gbGltaXRlZA==?=
Date: Wed, 14 Jul 2021 08:15:10 +0000
Content-Type: text/plain; charset=utf-8

Dear Customer,

We noticed unauthorized activity on your PayPal account. Please click the link below within 24 hours to verify your identity.

https://paypal-support-verify-acc.net/login

Sincerely,
PayPal Account Safety Team
`;

const GITHUB_NOTIFICATION_EML = `Delivered-To: dev@example.com
Received: from out-21.smtp.github.com ([192.30.252.204])
        by mx.google.com with SMTPS id gh1928374
        for <dev@example.com>;
        Fri, 20 Aug 2021 14:22:00 +0000
Authentication-Results: mx.google.com;
       dkim=pass header.i=@github.com;
       spf=pass (google.com: domain of support@github.com designates 192.30.252.204 as permitted sender);
       dmarc=pass header.from=github.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=github.com; s=pf2014;
        h=from:date:subject:to:message-id;
        bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=;
        b=N2o83K...
From: GitHub <notifications@github.com>
To: dev@example.com
Date: Fri, 20 Aug 2021 14:21:50 +0000
Message-ID: <github/projectemail/pull/12@github.com>
Subject: [GitHub] New Pull Request: Security updates and SPF/DKIM verification
Return-Path: <notifications@github.com>
Content-Type: text/plain; charset=utf-8

A new pull request has been opened in your repository.
`;

const AMAZON_ORDER_EML = `Delivered-To: customer@example.com
Received: from mm-notify-out-81.amazon.com ([54.240.13.81])
        by mx.inbound.net with ESMTPS id amz982341
        for <customer@example.com>;
        Tue, 10 Aug 2021 09:30:00 +0000
Authentication-Results: mx.inbound.net;
       dkim=pass header.i=@amazon.com;
       spf=pass (amazon.com: 54.240.13.81 is authorized);
       dmarc=pass header.from=amazon.com
From: "Amazon.com" <shipment-tracking@amazon.com>
Reply-To: shipment-tracking@amazon.com
To: customer@example.com
Subject: Your Amazon.com order #112-9842103-91823 has shipped!
Date: Tue, 10 Aug 2021 09:29:45 +0000
Message-ID: <0100017a12384-amazon-shipping@email.amazonses.com>
Content-Type: text/plain; charset=utf-8

Your package is on its way. Track your delivery at amazon.com/orders.
`;

const ANONYMOUSEMAIL_SAMPLE_EML = `Delivered-To: hr-manager@target-corp.com
Received: from mailout02.anonymousemail.eu ([185.107.56.22])
        by mx.target-corp.com with ESMTP id anon928114;
        Tue, 01 Sep 2026 11:20:00 +0000
DKIM-Signature: v=1; a=rsa-sha256; d=anonymousemail.eu; s=default;
Return-Path: <bounce@anonymousemail.eu>
Reply-To: whistle-contact@anonymousemail.me
From: "Anonymousemail Dispatch" <alert@anonymousemail.eu>
To: hr-manager@target-corp.com
Subject: URGENT: Anonymous Employee Grievance Notice
Date: Tue, 01 Sep 2026 11:20:00 +0000
Content-Type: text/plain; charset=utf-8

This report was dispatched anonymously via an external disposable mail relay server.`;

export async function seedInitialDatabase(database: Database): Promise<void> {
  const samples = [
    { account: "security@company.com", uid: "1000", raw: ANONYMOUSEMAIL_SAMPLE_EML },
    { account: "work@company.com", uid: "1001", raw: ORIGINAL_EML },
    { account: "security@company.com", uid: "1002", raw: SPOOFED_EML },
    { account: "security@company.com", uid: "1003", raw: PHISHING_PAYPAL_EML },
    { account: "dev@company.com", uid: "1004", raw: GITHUB_NOTIFICATION_EML },
    { account: "personal@inbox.com", uid: "1005", raw: AMAZON_ORDER_EML },
  ];

  for (const sample of samples) {
    try {
      const meta = await analyzeEmail(sample.raw);
      const aiNote = geminiService.generateFallbackNote({
        subject: meta.subject,
        from: meta.from_addr,
        from_name: meta.from_name,
        reply_to: meta.reply_to,
        return_path: meta.return_path,
        origin_ip: meta.ip_address,
        raw: sample.raw,
        spf_status: meta.spf?.status,
        dkim_status: meta.dkim?.status,
        dmarc_status: meta.dmarc?.status,
        threat_score: meta.risk_score,
        risk_level: meta.risk_level,
        findings: meta.findings,
      });
      database.upsertMessage(sample.account, sample.uid, meta, sample.raw, aiNote);
    } catch (e) {
      console.warn("Error seeding sample email:", e);
    }
  }
}
