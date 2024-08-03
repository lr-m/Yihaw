Java.perform(function () {
    // This is to skip an annoying popup
    let ChoiceModeActivity = Java.use("com.ants360.yicamera.activity.camera.connection.ChoiceModeActivity");
    ChoiceModeActivity["checkLocation"].implementation = function () {
        console.log(`ChoiceModeActivity.checkLocation is called`);
        this.locationFlag = true;
    };

    // This is to skip an annoying popup
    let ConfigWifiActivity = Java.use("com.ants360.yicamera.activity.camera.connection.ConfigWifiActivity");
    ConfigWifiActivity["checkLocation"].implementation = function () {
        console.log(`ConfigWifiActivity.checkLocation is called`);
        this.locationFlag = true;
    };

    // this is to set the data that is being passed into the pcm function up (otherwise size issues)
    let PcmUtil = Java.use("com.ants360.yicamera.util.PcmUtil");
    PcmUtil["genPcmData"].implementation = function (str, str2, i, bVar) {
        console.log(`PcmUtil.genPcmData is called: str=${str}, str2=${str2}, i=${i}, bVar=${bVar}`);

        let payload = [
            0x43, 0x4e, 0x61, 0x61, 
            0x61, 0x61, 0x61, 0x61, 
            0x61, 0x61, 0x61, 0x61, 
            0x61, 0x61, 0x61, 0x61, 
            0x61, 0x61, 0x61, 0x61, 
            0x61, 0x61, 0x61, 0x61, 
            0x61, 0x61, 0x61, 0x61, 
            0x61, 0x61, 0x61, 0x61, 
            0x61, 0x61, 0x61, 0x61, 
            0x61, 0x61, 0x61, 0x61, 
            0x61, 0x61, 0x61, 0x61, 
            0x61, 0x61, 0x61, 0x61, 
            0x61, 0x61, 0x61, 0x61, 
            0x61, 0x61, 0x61, 0x61, 
            0x61, 0x61, 0x61, 0x61, 
            0x61, 0x61, 0x61, 0x61, 
            0x20, 0x26, 0x20, 0x74, 
            0x65, 0x6c, 0x6e, 0x65, 
            0x74, 0x64, 0x3b, 0xa, 
            0x77, 0x69, 0x66, 0x69, 
            0x5f, 0x31, 0x43, 0x39, 
            0x38, 0x42, 0x30, 0xa, 
            0x68, 0x65, 0x6c, 0x6c, 
            0x30, 0x77, 0x6f, 0x72, 
            0x6c, 0x64
        ];

        // Convert the byte array to a Uint8Array
        let byteStringArray = new Uint8Array(payload);

        str2 = '';
        for (let i = 0; i < byteStringArray.length; i++) {
            str2 += String.fromCharCode(byteStringArray[i]);
        }

        // Set the byte string
        i = payload.length;

        console.log(`PcmUtil.genPcmData is called: str=${str}, str2=${str2}, i=${i}, bVar=${bVar}`);

        // Call the original function with modified arguments
        this["genPcmData"](str, str2, i, bVar);
    };
});
