import express from 'express';
import { engine } from 'express-handlebars';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
import crypto from 'crypto';

app.engine('handlebars', engine());
app.set('view engine', 'handlebars');
app.set('views', './views');
app.use(express.static('public'))

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.get('/login', (req, res) => {
    console.log(req.query)

    res.render('index', {
        layout: false,
        wlan_id: req.query.wlan_id,
        ap_mac: req.query.ap_mac,
        client_mac: req.query.client_mac,
        url: req.query.url,
        ap_name: req.query.ap_name,
        site_name: req.query.site_name
    });
});


app.get('/home', (req, res) => {
    res.render('home', {layout: false})
});

app.post('/authentication', (req, res) => {

    console.log(req.body);

    //let secret = process.env.SECRET;
    let secret = 'test-secret';
    let wlan_id = req.body.wlan_id;
    let ap_mac = req.body.ap_mac;
    let client_mac = req.body.client_mac;

    let url = "http://localhost:3000/home"; //Ver URL de deploy

    let ap_name = req.body.ap_name;
    let site_name = req.body.site_name;

    let authorize_min = 525600;  // Duration (in minutes) the guest MAC address is authorized before they are redirected back to the portal page
    let download_kbps = 0;  // Download limit (in kbps) per client. Recommended to leave as 0 (unlimited), as this can be set globally in the WLAN
    let upload_kbps = 0;  // Upload limit (in kbps) per client. Recommended to leave as 0 (unlimited), as this can be set globally in the WLAN
    let quota_mbytes = 0;  // Quota (in mbytes) per client. Recommended to leave as 0 (unlimited)

    let context = `${wlan_id}/${ap_mac}/${client_mac}/${authorize_min}/${download_kbps}/${upload_kbps}/${quota_mbytes}`;
    let token = encodeURIComponent(Buffer.from(context).toString('base64'));

    let name = req.body.name;
    let email = req.body.email;

    let forward = encodeURIComponent(url);
    let extra = '&forward=' + forward;
    extra += '&name=' + encodeURIComponent(name);
    extra += '&email=' + encodeURIComponent(email);
    let expires = Math.floor(Date.now() / 1000) + 6050;
    let payload = 'expires=' + expires + '&token=' + token + extra;

    let hmac = crypto.createHmac('sha1', secret);
    hmac.update(payload);
    let signature = encodeURIComponent(Buffer.from(hmac.digest()).toString('base64'));

    let final_url = 'https://portal.mist.com/authorize-test?signature=' + signature + '&' + payload;
    //let final_url = 'https://portal.mist.com/authorize?signature=' + signature + '&' + payload;

    var debugging = false;

    if (debugging) {
        var response = {
            status: "success",
            message: "Usuario agregado correctamente!",
            "token : urlencode(base64(%s))": context + "\n",
            " %s": token + "\n",
            forward: url + "\n",
            "payload-to-sign": payload + "\n",
            signature: signature + "\n",
            URL: final_url + "\n",
            client_mac: client_mac + "\n",
            ap_mac: ap_mac + "\n",
            ap_name: ap_name + "\n",
            wlan_id: wlan_id + "\n",
            site_name: site_name + "\n",
            name: name + "\n",
            email: email + "\n",
        };
        res.json(response);
    } else {
        console.error(final_url);

        // Guest is redirected to the Mist portal for authorization. If successful, the Mist portal will then redirect the guest to the $url
        var response = {
            status: "success",
            message: "Usuario conectado correctamente!",
            url: url,
            name: name,
        };
        res.json(response);
    }
})

app.listen(3000, () => {
    console.log('Server is running on port 3000');
});
