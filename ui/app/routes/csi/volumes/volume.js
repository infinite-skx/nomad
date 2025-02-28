import { inject as service } from '@ember/service';
import Route from '@ember/routing/route';
import { collect } from '@ember/object/computed';
import RSVP from 'rsvp';
import notifyError from 'nomad-ui/utils/notify-error';
import { watchRecord } from 'nomad-ui/utils/properties/watch';
import WithWatchers from 'nomad-ui/mixins/with-watchers';
import classic from 'ember-classic-decorator';

@classic
export default class VolumeRoute extends Route.extend(WithWatchers) {
  @service store;
  @service system;

  startWatchers(controller, model) {
    if (!model) return;

    controller.set('watchers', {
      model: this.watch.perform(model),
    });
  }

  serialize(model) {
    return { volume_name: model.get('plainId') };
  }

  model(params, transition) {
    const namespace = transition.to.queryParams.namespace;
    const name = params.volume_name;
    const fullId = JSON.stringify([`csi/${name}`, namespace || 'default']);
    return RSVP.hash({
      volume: this.store.findRecord('volume', fullId, { reload: true }),
      namespaces: this.store.findAll('namespace'),
    })
      .then(hash => hash.volume)
      .catch(notifyError(this));
  }

  // Since volume includes embedded records for allocations,
  // it's possible that allocations that are server-side deleted may
  // not be removed from the UI while sitting on the volume detail page.
  @watchRecord('volume') watch;
  @collect('watch') watchers;
}
