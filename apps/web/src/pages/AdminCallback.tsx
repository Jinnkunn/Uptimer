import { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';

import { useAuth } from '../app/AuthContext';
import { useI18n } from '../app/I18nContext';
import { ADMIN_LOGIN_PATH } from '../app/adminPaths';
import { finishOidcLogin } from '../auth/oidc';
import { Button, Card } from '../components/ui';

export function AdminCallback() {
  const { t } = useI18n();
  const { login } = useAuth();
  const navigate = useNavigate();
  const didRun = useRef(false);
  const [error, setError] = useState('');

  useEffect(() => {
    document.title = t('admin_login.callback_title');
  }, [t]);

  useEffect(() => {
    if (didRun.current) return;
    didRun.current = true;

    finishOidcLogin(window.location.href)
      .then(async ({ accessToken, returnTo }) => {
        await login(accessToken);
        navigate(returnTo, { replace: true });
      })
      .catch(() => {
        setError(t('admin_login.callback_error'));
      });
  }, [login, navigate, t]);

  return (
    <div className="flex min-h-screen items-center justify-center bg-slate-50 p-4 dark:bg-slate-900 sm:p-6">
      <Card className="w-full max-w-md p-7 text-center sm:p-8">
        <h1 className="text-xl font-semibold text-slate-900 dark:text-slate-100">
          {t('admin_login.callback_title')}
        </h1>
        {error ? (
          <>
            <p className="mt-3 text-sm text-slate-500 dark:text-slate-400">{error}</p>
            <Button onClick={() => navigate(ADMIN_LOGIN_PATH)} className="mt-6 w-full">
              {t('admin_login.submit')}
            </Button>
          </>
        ) : (
          <p className="mt-3 text-sm text-slate-500 dark:text-slate-400">
            {t('common.loading_ellipsis')}
          </p>
        )}
      </Card>
    </div>
  );
}
