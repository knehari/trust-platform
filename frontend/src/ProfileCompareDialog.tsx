import { useEffect, useRef } from 'react';
import type { ProfileDraft } from './api';
import { compareProfileRevisions } from './profile-compare';

export function ProfileCompareDialog({ first, second, onClose }: { first: ProfileDraft; second: ProfileDraft; onClose: () => void }) {
  const dialog = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const element = dialog.current;
    element?.showModal();
    return () => element?.close();
  }, []);
  const differences = compareProfileRevisions(first, second);
  const changed = differences.filter(row => row.changed).length;
  return <dialog ref={dialog} className="certificate-dialog profile-compare-dialog" aria-labelledby="profile-compare-title" onClose={onClose}>
    <div className="dialog-heading"><div><div className="eyebrow">DRAFT COMPARISON</div><h2 id="profile-compare-title">Revision comparison</h2></div><button type="button" className="dialog-close" aria-label="Close revision comparison" onClick={() => dialog.current?.close()}><span aria-hidden="true">×</span></button></div>
    <p className="profile-draft-message">{first.profile_id} · {changed} fields differ across two loaded revisions.</p>
    <div className="profile-compare-scroll"><table className="profile-compare-table"><thead><tr><th>Field</th><th>Earlier revision</th><th>Later revision</th></tr></thead><tbody>{differences.map(row => <tr key={row.label} className={row.changed ? 'changed' : ''}><th scope="row">{row.label}</th><td>{row.before}</td><td>{row.after}</td></tr>)}</tbody></table></div>
    <p className="dialog-note">This comparison is informational. It does not approve or activate either proposal; the digests identify proposal content, not signed approval evidence.</p>
  </dialog>;
}
