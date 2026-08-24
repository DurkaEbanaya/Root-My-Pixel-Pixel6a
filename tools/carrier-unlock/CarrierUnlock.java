import java.lang.reflect.Method;

import android.os.IBinder;
import android.os.Looper;

/**
 * Minimal app_process helper for inspecting and clearing carrier restrictions.
 *
 * This intentionally uses reflection: ITelephony and ServiceManager are hidden
 * Android APIs and differ slightly between releases.
 */
public final class CarrierUnlock {
    private CarrierUnlock() {}

    private static void fatal(String message) {
        System.err.println("ERROR: " + message);
        System.exit(1);
    }

    private static Method noArgMethod(Object target, String name) {
        for (Method method : target.getClass().getMethods()) {
            if (method.getName().equals(name) && method.getParameterCount() == 0) {
                return method;
            }
        }
        return null;
    }

    private static Method oneArgMethod(Object target, String name) {
        for (Method method : target.getClass().getMethods()) {
            if (method.getName().equals(name) && method.getParameterCount() == 1) {
                return method;
            }
        }
        return null;
    }

    public static void main(String[] args) {
        try {
            Looper.prepareMainLooper();

            Class<?> serviceManager = Class.forName("android.os.ServiceManager");
            Method getService = serviceManager.getMethod("getService", String.class);
            IBinder binder = (IBinder) getService.invoke(null, "phone");
            System.out.println("phone binder: " + binder);
            if (binder == null) {
                fatal("phone binder is null");
                return;
            }

            Class<?> stub = Class.forName("com.android.internal.telephony.ITelephony$Stub");
            Object telephony = stub.getMethod("asInterface", IBinder.class).invoke(null, binder);
            System.out.println("itelephony proxy: " + telephony.getClass().getName());

            Method getAllowed = noArgMethod(telephony, "getAllowedCarriers");
            if (getAllowed == null) {
                fatal("getAllowedCarriers() NOT FOUND");
                return;
            }

            Object before = getAllowed.invoke(telephony);
            System.out.println("before: " + before);

            if (args.length == 0 || !"clear".equals(args[0])) {
                return;
            }

            Class<?> rules = Class.forName("android.telephony.CarrierRestrictionRules");
            Class<?> builderClass = Class.forName(
                    "android.telephony.CarrierRestrictionRules$Builder");
            Object builder = rules.getMethod("newBuilder").invoke(null);
            builderClass.getMethod("setAllCarriersAllowed").invoke(builder);
            Object newRules = builderClass.getMethod("build").invoke(builder);
            System.out.println("new rules: " + newRules);

            Method setAllowed = oneArgMethod(telephony, "setAllowedCarriers");
            if (setAllowed == null) {
                fatal("setAllowedCarriers(rules) NOT FOUND");
                return;
            }

            System.out.println("invoking " + setAllowed);
            Object result = setAllowed.invoke(telephony, newRules);
            System.out.println("setAllowedCarriers -> " + result);
            if (!(result instanceof Integer) || ((Integer) result).intValue() != 0) {
                fatal("setAllowedCarriers returned " + result);
                return;
            }

            Thread.sleep(2500);
            System.out.println("readback: " + getAllowed.invoke(telephony));
        } catch (Throwable error) {
            System.err.println("ERROR: " + error);
            for (Throwable cause = error.getCause(); cause != null; cause = cause.getCause()) {
                System.err.println("  caused by: " + cause);
            }
            System.exit(1);
        }
    }
}
