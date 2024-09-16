package vendor.xiaomi.hw.touchfeature;

@VintfStability
interface ITouchFeature {
    int setModeValue(int touchId, int ControlMode, int ModeValue);
    int getModeCurValue(int touchId, int ControlMode);
    String getModeCurValueString(int touchId, int ControlMode);
    int getModeMaxValue(int touchId, int ControlMode);
    int getModeMinValue(int touchId, int ControlMode);
    int getModeDefaultValue(int touchId, int ControlMode);
    int modeReset(int touchId, int ControlMode);
    int[] getModeValue(int touchId, int mode);
    int setModeLongValue(int touchId, int ControlMode, int ValueLen, inout int[] ValueBuf);
    String getModeWhiteList(int ValueLen, inout int[] ValueBuf);
    String getTouchEvent();
}
