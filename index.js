 1 | const express = require('express');
 2 | const bodyParser = require('body-parser');
 3 | const cors = require('cors');
 4 | const session = require('express-session');
 5 | const cookieParser = require('cookie-parser');
 6 | const twilio = require('twilio');
 7 |
 8 | const app = express();
 9 | const PORT = process.env.PORT || 10000;
10 |
11 | // ---------- Middleware ----------
12 | app.use(bodyParser.json());
13 | app.use(cookieParser());
14 | app.use(cors({
15 |   origin: process.env.CORS_ORIGIN || '*',
16 |   credentials: true
17 | }));
18 |
19 | app.use(session({
20 |   secret: process.env.SESSION_SECRET || 'devsecret',
21 |   resave: false,
22 |   saveUninitialized: true,
23 |   cookie: { secure: false }
24 | }));
25 |
26 | // ---------- Twilio Setup ----------
27 | const client = twilio(
28 |   process.env.TWILIO_SID,
29 |   process.env.TWILIO_AUTH_TOKEN
30 | );
31 | const TWILIO_PHONE = process.env.TWILIO_PHONE_NUMBER;
32 |
33 | // ---------- In-Memory Stores ----------
34 | let otpStore = {};          // { phone: code }
35 | let appointments = {};      // { phone: { time, code } }
36 |
37 | // ---------- Request OTP ----------
38 | app.post('/auth/request-code', async (req, res) => {
39 |   const { phone } = req.body;
40 |   if (!phone) return res.status(400).json({ error: 'Missing phone' });
41 |
42 |   const code = Math.floor(100000 + Math.random() * 900000).toString();
43 |   otpStore[phone] = code;
44 |
45 |   try {
46 |     await client.messages.create({
47 |       body: `Your verification code is: ${code}\nText STOP to opt out.`,
48 |       from: TWILIO_PHONE,
49 |       to: phone
50 |     });
51 |     res.json({ success: true });
52 |   } catch (err) {
53 |     console.error('Twilio error', err);
54 |     res.status(500).json({ error: 'Failed to send code' });
55 |   }
56 | });
57 |
58 | // ---------- Verify OTP ----------
59 | app.post('/auth/verify', (req, res) => {
60 |   const { phone, code } = req.body;
61 |   if (otpStore[phone] === code) {
62 |     req.session.phone = phone;
63 |     delete otpStore[phone];
64 |     res.json({ ok: true });
65 |   } else {
66 |     res.status(400).json({ ok: false });
67 |   }
68 | });
69 |
70 | // ---------- Book Appointment ----------
71 | app.post('/api/appointments', (req, res) => {
72 |   const { phone, time } = req.body;
73 |   if (!phone || !time) return res.status(400).json({ error: 'Missing data' });
74 |
75 |   // generate random 4-digit probe code
76 |   const probeCode = Math.floor(1000 + Math.random() * 9000).toString();
77 |   appointments[phone] = { time, code: probeCode };
78 |
79 |   // send confirmation SMS
80 |   client.messages.create({
81 |     body: `Appointment confirmed for ${time}. Your probe code: ${probeCode}`,
82 |     from: TWILIO_PHONE,
83 |     to: phone
84 |   }).catch(err => console.error('Twilio send failed', err));
85 |
86 |   res.json({ success: true, time, probeCode });
87 | });
88 |
89 | // ---------- Get Appointments ----------
90 | app.get('/api/appointments', (req, res) => {
91 |   res.json(appointments);
92 | });
93 |
94 | // ---------- Notify Only ----------
95 | app.post('/api/notify', (req, res) => {
96 |   const { phone, message } = req.body;
97 |   if (!phone || !message) return res.status(400).json({ error: 'Missing data' });
98 |
99 |   client.messages.create({
100|     body: message,
101|     from: TWILIO_PHONE,
102|     to: phone
103|   }).then(() => res.json({ success: true }))
104|     .catch(err => {
105|       console.error('Notify failed', err);
106|       res.status(500).json({ error: 'Failed to notify' });
107|     });
108| });
109|
110| // ---------- Static Files ----------
111| app.use(express.static('public'));
112|
113| // ---------- Start ----------
114| app.listen(PORT, () => {
115|   console.log(`Server running on http://localhost:${PORT}`);
116| });
